import logging
import uuid

from airflow.decorators import task
from airflow.exceptions import AirflowSkipException
from airflow.providers.postgres.hooks.postgres import PostgresHook
from airflow.providers.redis.hooks.redis import RedisHook
from psycopg2.extras import Json

from constants import (
    SQL_CHANGE_WITH_VENDORS,
    SQL_PROJECT_WITH_SUBSCRIPTIONS,
    SQL_PROCEDURES,
    PRODUCT_SEPARATOR,
)
from utils import (
    decode_hmap,
    get_project_subscriptions,
    get_vendor_changes,
    get_reports,
)

logger = logging.getLogger(__name__)


def get_start_end_dates(context):
    start = context.get("data_interval_start")
    end = context.get("data_interval_end").subtract(seconds=1)
    return start, end


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
    redis_hook.json().set(f"changes_{start}_{end}", "$", changes)


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
    report_id = str(uuid.uuid4())
    for project_id, changes_id in reports.items():
        hook.run(
            sql=SQL_PROCEDURES.get("report"),
            parameters={
                "report": report_id,
                "project": project_id,
                "created": start,  # TODO: début de journée, là c'est start de l'interval
                "changes": Json(changes_id),
            },
        )
