import logging

from airflow.decorators import task
from airflow.providers.postgres.hooks.postgres import PostgresHook

from includes.constants import WEAKNESS_UPSERT_PROCEDURE
from includes.utils import fetch_weaknesses

logger = logging.getLogger(__name__)


@task(task_id="sync_weaknesses")
def sync_weaknesses(**context):
    weaknesses = fetch_weaknesses()
    hook = PostgresHook(postgres_conn_id="opencve_postgres")
    synced_at = context["logical_date"]

    logger.info("Found %s weaknesses", len(weaknesses))

    for weakness in weaknesses:
        hook.run(
            sql=WEAKNESS_UPSERT_PROCEDURE,
            parameters={
                "cwe": f"CWE-{weakness['id']}",
                "created": synced_at,
                "updated": synced_at,
                "name": weakness["name"],
                "description": weakness["description"],
            },
        )

    logger.info("Synced %s weaknesses", len(weaknesses))
