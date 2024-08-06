import logging
import uuid

from airflow.decorators import task
from airflow.exceptions import AirflowSkipException
from airflow.providers.postgres.hooks.postgres import PostgresHook
from airflow.providers.redis.hooks.redis import RedisHook
from includes.constants import (
    PRODUCT_SEPARATOR,
    REPORT_UPSERT_PROCEDURE,
    SQL_CHANGE_WITH_VENDORS,
    SQL_PROJECT_WITH_SUBSCRIPTIONS,
)
from includes.utils import (
    format_change_details,
    list_changes_by_project,
    merge_project_subscriptions,
    get_dates_from_context,
    group_changes_by_vendor,
    list_commits,
)
from psycopg2.extras import Json

logger = logging.getLogger(__name__)


@task
def list_changes(**context):
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    postgres_hook = PostgresHook(postgres_conn_id="opencve_postgres")
    start, end = get_dates_from_context(context)

    # Get the list of changes with their associated vendors
    commits = [
        c.hexsha
        for c in list_commits(
            logger=logger,
            start=context.get("data_interval_start"),
            end=context.get("data_interval_end"),
        )
    ]
    if not commits:
        raise AirflowSkipException("No commit found")

    logger.info("Listing associated changes in %s table", "opencve_changes")
    records = postgres_hook.get_records(
        sql=SQL_CHANGE_WITH_VENDORS, parameters={"commits": tuple(commits)}
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
        raise AirflowSkipException("No change with vendor found")

    key = f"changes_details_{start}_{end}"
    logger.info("Saving %s changes in Redis (key: %s)", str(len(change_details)), key)
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
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    postgres_hook = PostgresHook(postgres_conn_id="opencve_postgres")
    start, end = get_dates_from_context(context)

    # Get the list of changes
    changes_redis_key = f"vendor_changes_{start}_{end}"
    logger.info(
        "Fetching changes between %s and %s using Redis (key: %s)",
        start,
        end,
        changes_redis_key,
    )
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
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    start, end = get_dates_from_context(context)

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
        hook.run(
            sql=REPORT_UPSERT_PROCEDURE,
            parameters={
                "report": report_id,
                "project": project_id,
                "day": start,
                "changes": Json(changes_id),
            },
        )
