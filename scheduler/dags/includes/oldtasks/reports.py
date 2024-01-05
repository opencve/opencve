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
    SQL_PROCEDURES,
    PRODUCT_SEPARATOR,
)
from includes.tasks import get_start_end_dates
from includes.utils import (
    get_project_subscriptions,
    get_vendor_changes,
    get_reports,
)

logger = logging.getLogger(__name__)


@task
def get_changes(**context):
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    postgres_hook = PostgresHook(postgres_conn_id="opencve_postgres")
    start, end = get_start_end_dates(context)

    # Get the list of changes with their associated vendors
    records = postgres_hook.get_records(
        sql=SQL_CHANGE_WITH_VENDORS, parameters={"start": start, "end": end}
    )

    # Group the change by vendors
    changes = get_vendor_changes(records)
    if not changes:
        raise AirflowSkipException(f"No vendor changes from {start} to {end}")
    else:
        logger.info(f"Got {len(changes)} vendors/products with changes: {changes}")

    # Save the result in redis
    key = f"changes_{start}_{end}"
    redis_hook.json().set(key, "$", changes)
    redis_hook.expire(key, 60 * 60 * 24)


@task
def get_subscriptions(**context):
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    postgres_hook = PostgresHook(postgres_conn_id="opencve_postgres")
    start, end = get_start_end_dates(context)

    # Get the list of changes
    changes = redis_hook.json().objkeys(f"changes_{start}_{end}")
    if not changes:
        raise AirflowSkipException(f"No change from {start} to {end}")

    # Extract vendors & products based on the separator
    vendors = [c for c in changes if PRODUCT_SEPARATOR not in c]
    logger.info(f"Got {len(vendors)} vendors: {vendors}")
    products = [c for c in changes if PRODUCT_SEPARATOR in c]
    logger.info(f"Got {len(products)} products: {products}")

    # List the projects with subscriptions to these vendors & products
    records = postgres_hook.get_records(
        sql=SQL_PROJECT_WITH_SUBSCRIPTIONS,
        parameters={"vendors": vendors, "products": products},
    )
    items = get_project_subscriptions(records)

    # Save the result in redis
    key = f"subscriptions_{start}_{end}"
    redis_hook.json().set(key, "$", items)
    redis_hook.expire(key, 60 * 60 * 24)


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
            sql=SQL_PROCEDURES.get("report"),
            parameters={
                "report": report_id,
                "project": project_id,
                "day": start,
                "changes": Json(changes_id),
            },
        )
