import logging
import uuid

from airflow.decorators import task
from airflow.exceptions import AirflowSkipException
from airflow.providers.postgres.hooks.postgres import PostgresHook
from airflow.providers.redis.hooks.redis import RedisHook
from psycopg2.extras import Json

from includes.constants import (
    SQL_CHANGE_WITH_VENDORS,
    SQL_PROJECT_WITH_SUBSCRIPTIONS,
    PRODUCT_SEPARATOR,
    REPORT_UPSERT_PROCEDURE,
)
from includes.utils import (
    get_project_subscriptions,
    get_start_end_dates,
    get_vendor_changes,
    get_reports,
    list_commits,
)

logger = logging.getLogger(__name__)


@task
def list_changes(**context):
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    postgres_hook = PostgresHook(postgres_conn_id="opencve_postgres")
    start, end = get_start_end_dates(context)

    # Get the list of changes with their associated vendors
    commits = [c.hexsha for c in list_commits(
        logger=logger,
        start=context.get("data_interval_start"),
        end=context.get("data_interval_end")
    )]
    logger.info("Listing associated changes in %s table", "opencve_changes")
    records = postgres_hook.get_records(
        sql=SQL_CHANGE_WITH_VENDORS, parameters={"commits": tuple(commits)}
    )

    # Group the change by vendors
    changes = get_vendor_changes(records)
    if not changes:
        logger.info("No change found")
        return

    # Save the result in redis
    key = f"changes_{start}_{end}"
    logger.info(f"Got %s vendors/products with changes: %s, saving it in Redis (key: %s)", str(len(changes)), changes, key)
    redis_hook.json().set(key, "$", changes)
    redis_hook.expire(key, 60 * 60 * 24)


@task
def list_subscriptions(**context):
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    postgres_hook = PostgresHook(postgres_conn_id="opencve_postgres")
    start, end = get_start_end_dates(context)

    # Get the list of changes
    changes_redis_key = f"changes_{start}_{end}"
    logger.info("Fetching changes between %s and %s using Redis (key: %s)", start, end, changes_redis_key)
    changes = redis_hook.json().objkeys(changes_redis_key)
    if not changes:
        logger.info("No change found")
        return

    # Extract vendors & products based on the separator
    vendors = [c for c in changes if PRODUCT_SEPARATOR not in c]
    products = [c for c in changes if PRODUCT_SEPARATOR in c]
    logger.info(f"Found %s vendors (%s) and %s products (%s)", str(len(vendors)), ", ".join(vendors), str(len(products)), ", ".join(products))

    # List the projects with subscriptions to these vendors & products
    logger.info("Listing subscriptions in %s table for these vendors and products", "opencve_projects")
    records = postgres_hook.get_records(
        sql=SQL_PROJECT_WITH_SUBSCRIPTIONS,
        parameters={"vendors": vendors, "products": products},
    )

    subscriptions = get_project_subscriptions(records)
    if not subscriptions:
        logger.info("No subscription found")
        return

    # Save the result in redis
    subscriptions_key = f"subscriptions_{start}_{end}"
    logger.info("Found %s subscribed projects, saving it in Redis (key: %s)", str(len(subscriptions)), subscriptions_key)
    redis_hook.json().set(subscriptions_key, "$", subscriptions)
    redis_hook.expire(subscriptions_key, 60 * 60 * 24)


@task
def populate_reports(**context):
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    start, end = get_start_end_dates(context)

    # Get the list of changes
    changes = redis_hook.json().get(f"changes_{start}_{end}")
    if not changes:
        raise AirflowSkipException(f"No change from {start} to {end}")

    # Get the list of subscriptions
    subscriptions = redis_hook.json().get(f"subscriptions_{start}_{end}")
    if not subscriptions:
        raise AirflowSkipException(f"No subscriptions from {start} to {end}")

    # Associate each project to its changes
    reports = get_reports(changes, subscriptions)
    logger.info(f"Got {len(reports)} reports to insert in database")

    # Create the reports for each project
    hook = PostgresHook(postgres_conn_id="opencve_postgres")

    for project_id, changes_id in reports.items():
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
