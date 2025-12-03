import logging
import pathlib
import json
import uuid
import time

from airflow.configuration import conf
from airflow.decorators import task
from airflow.exceptions import AirflowSkipException, AirflowConfigException
from airflow.providers.postgres.hooks.postgres import PostgresHook
from airflow.providers.redis.hooks.redis import RedisHook
from psycopg2.errors import ForeignKeyViolation
from includes.constants import (
    PRODUCT_SEPARATOR,
    REPORT_UPSERT_PROCEDURE,
    SQL_CHANGE_WITH_VENDORS,
    SQL_PROJECT_WITH_SUBSCRIPTIONS,
    SQL_REPORTS_CVES_BY_DAY,
    SQL_UPDATE_REPORT_AI_SUMMARY,
)
from includes.utils import (
    format_change_details,
    list_changes_by_project,
    merge_project_subscriptions,
    get_dates_from_context,
    group_changes_by_vendor,
    call_llm,
    build_user_content_for_llm,
)
from psycopg2.extras import Json

logger = logging.getLogger(__name__)


@task
def list_changes(**context):
    start, end = get_dates_from_context(context)

    logger.info(
        "Listing changes between %s and %s in %s table", start, end, "opencve_changes"
    )
    postgres_hook = PostgresHook(postgres_conn_id="opencve_postgres")
    records = postgres_hook.get_records(
        sql=SQL_CHANGE_WITH_VENDORS, parameters={"start": start, "end": end}
    )
    if not records:
        raise AirflowSkipException("No change found")

    # Save the change details in redis
    change_details = format_change_details(records)
    logger.debug("List of changes: %s", change_details)

    # Save the change by vendors in redis
    vendor_changes = group_changes_by_vendor(records)
    logger.debug("List of changes by vendor: %s", vendor_changes)

    if not vendor_changes:
        raise AirflowSkipException("No vendor with change found")

    key = f"changes_details_{start}_{end}"
    logger.info("Saving %s changes in Redis (key: %s)", str(len(change_details)), key)
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    redis_hook.json().set(key, "$", change_details)
    redis_hook.expire(key, 60 * 60 * 24)

    key = f"vendor_changes_{start}_{end}"
    logger.info(
        "Saving %s vendors/products in Redis (key: %s)", str(len(vendor_changes)), key
    )
    redis_hook.json().set(key, "$", vendor_changes)
    redis_hook.expire(key, 60 * 60 * 24)


@task
def list_subscriptions(**context):
    start, end = get_dates_from_context(context)

    # Get the list of changes
    changes_redis_key = f"vendor_changes_{start}_{end}"
    logger.info(
        "Fetching changes between %s and %s using Redis (key: %s)",
        start,
        end,
        changes_redis_key,
    )
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    changes = redis_hook.json().objkeys(changes_redis_key)

    # Extract vendors & products based on the separator
    vendors = [c for c in changes if PRODUCT_SEPARATOR not in c]
    products = [c for c in changes if PRODUCT_SEPARATOR in c]
    logger.info(
        "Found %s vendors (%s) and %s products (%s)",
        str(len(vendors)),
        ", ".join(vendors),
        str(len(products)),
        ", ".join(products),
    )

    # List the projects with subscriptions to these vendors & products
    logger.info(
        "Listing subscriptions in %s table for these vendors and products",
        "opencve_projects",
    )
    postgres_hook = PostgresHook(postgres_conn_id="opencve_postgres")
    records = postgres_hook.get_records(
        sql=SQL_PROJECT_WITH_SUBSCRIPTIONS,
        parameters={"vendors": vendors, "products": products},
    )

    subscriptions = merge_project_subscriptions(records)
    if not subscriptions:
        raise AirflowSkipException("No subscription found")

    # Save the result in redis
    subscriptions_key = f"subscriptions_{start}_{end}"
    logger.info(
        "Found %s subscribed projects, saving it in Redis (key: %s)",
        str(len(subscriptions)),
        subscriptions_key,
    )
    logger.debug("List of subscriptions: %s", subscriptions)
    redis_hook.json().set(subscriptions_key, "$", subscriptions)
    redis_hook.expire(subscriptions_key, 60 * 60 * 24)


@task
def populate_reports(**context):
    start, end = get_dates_from_context(context)

    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    changes = redis_hook.json().get(f"vendor_changes_{start}_{end}")
    subscriptions = redis_hook.json().get(f"subscriptions_{start}_{end}")

    # Associate each project to its changes
    project_changes = list_changes_by_project(changes, subscriptions)
    logger.info("Found %s reports to create", str(len(project_changes)))

    key = f"project_changes_{start}_{end}"
    logger.info("Saving changes by project in Redis (key: %s)", key)
    redis_hook.json().set(key, "$", project_changes)
    redis_hook.expire(key, 60 * 60 * 24)

    # Create the reports for each project
    hook = PostgresHook(postgres_conn_id="opencve_postgres")

    for project_id, changes_id in project_changes.items():
        report_id = str(uuid.uuid4())

        try:
            hook.run(
                sql=REPORT_UPSERT_PROCEDURE,
                parameters={
                    "report": report_id,
                    "project": project_id,
                    "day": start,
                    "changes": Json(changes_id),
                },
            )

        # It is possible that a user deletes a project before this task
        # runs, but after the project_id has been saved in redis by the
        # `list_subscriptions` task.
        except ForeignKeyViolation as e:
            error_msg = 'insert or update on table "opencve_reports" violates foreign key constraint'
            if str(e).startswith(error_msg):
                logger.info(f"Project {project_id} does not exist anymore")


@task
def summarize_reports(**context):
    """
    This task is used to generate summaries for each report.
    """

    # First we check if the LLM is well configured
    try:
        llm_api_key = conf.get("opencve", "llm_api_key")
    except AirflowConfigException:
        raise AirflowSkipException("LLM API key is not configured")

    try:
        llm_api_url = conf.get("opencve", "llm_api_url")
    except AirflowConfigException:
        raise AirflowSkipException("LLM API URL is not configured")

    try:
        llm_model = conf.get("opencve", "llm_model")
    except AirflowConfigException:
        llm_model = "Mistral-7B-Instruct-v0.3"

    # Retrieve the reports for the last day
    last_day = str(context["data_interval_start"].date())
    logger.info("Retrieving reports for day %s", last_day)

    hook = PostgresHook(postgres_conn_id="opencve_postgres")
    reports = hook.get_records(
        sql=SQL_REPORTS_CVES_BY_DAY,
        parameters={"day": last_day},
    )

    # LLM system prompt
    prompt_path = (
        pathlib.Path(__file__).parent.parent / "data" / "summarize_reports.prompt"
    )
    with open(prompt_path, "r") as f:
        system_prompt = f.read()

    for report in reports:
        report_id = report[0]
        report_cves = report[1]
        report_cves_count = report[2]
        report_cves_score_distribution = report[3]
        logger.info("Processing report %s with %s CVEs", report_id, report_cves_count)

        user_content_for_llm = build_user_content_for_llm(
            report_cves, report_cves_count, report_cves_score_distribution
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content_for_llm},
        ]

        # Call the LLM
        logger.info("Calling LLM for report %s", report_id)
        start_time = time.time()
        response = call_llm(llm_api_key, llm_api_url, llm_model, messages, logger)

        # If the LLM response is None, skip the report
        if response is None:
            continue

        logger.info(
            "LLM response for report %s in %s seconds",
            report_id,
            time.time() - start_time,
        )

        # Update the report with the LLM response
        logger.info("Updating report %s with LLM response", report_id)
        hook.run(
            sql=SQL_UPDATE_REPORT_AI_SUMMARY,
            parameters={"report_id": report_id, "ai_summary": response},
        )
