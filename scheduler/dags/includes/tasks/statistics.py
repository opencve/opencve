import logging

from airflow.decorators import task
from airflow.providers.postgres.hooks.postgres import PostgresHook
from psycopg2.extras import Json

from includes.constants import (
    SQL_CVES_EVOLUTION_STATISTICS,
    VARIABLE_UPSERT_PROCEDURE,
    SQL_CVSS_ROUNDED_SCORES,
    SQL_CVSS_CATEGORIZED_SCORES,
    SQL_CVES_TOP_VENDORS,
    SQL_CVES_TOP_PRODUCTS,
    SQL_CVES_COUNT_LAST_DAYS,
)

logger = logging.getLogger(__name__)


def insert_variable(name, value):
    hook = PostgresHook(postgres_conn_id="opencve_postgres")
    hook.run(
        sql=VARIABLE_UPSERT_PROCEDURE,
        parameters={
            "p_name": name,
            "p_value": Json(value),
        },
    )


@task
def compute_statistics(**context):
    logger.info("Computing statistics")
    hook = PostgresHook(postgres_conn_id="opencve_postgres")

    # CVEs statistics
    records = hook.get_records(sql=SQL_CVES_EVOLUTION_STATISTICS)
    cves_yearly_counts = {r[0]: r[1] for r in records}
    insert_variable("statistics_cves_yearly_counts", cves_yearly_counts)

    cves_cumulative_counts = {r[0]: r[2] for r in records}
    insert_variable("statistics_cves_cumulative_counts", cves_cumulative_counts)

    records = hook.get_records(sql=SQL_CVES_COUNT_LAST_DAYS)[0]
    cves_count_last_days = {
        "24_hours": {
            "last": records[0],
            "prev": records[4],
            "ratio": float(records[8]) if records[8] else None,
        },
        "7_days": {
            "last": records[1],
            "prev": records[5],
            "ratio": float(records[9]) if records[9] else None,
        },
        "30_days": {
            "last": records[2],
            "prev": records[6],
            "ratio": float(records[10]) if records[10] else None,
        },
        "90_days": {
            "last": records[3],
            "prev": records[7],
            "ratio": float(records[11]) if records[11] else None,
        },
    }

    insert_variable("statistics_cves_count_last_days", cves_count_last_days)

    # CVSS metrics statistics
    cvss_rounded_scores = {}
    cvss_categorized_scores = {}

    for metric in ["cvssV2_0", "cvssV3_0", "cvssV3_1", "cvssV4_0"]:
        records = hook.get_records(sql=SQL_CVSS_ROUNDED_SCORES.format(metric=metric))
        cvss_rounded_scores[metric] = {r[0]: r[1] for r in records}

        records = hook.get_records(
            sql=SQL_CVSS_CATEGORIZED_SCORES.format(metric=metric)
        )
        cvss_categorized_scores[metric] = {r[0]: r[1] for r in records}

    insert_variable("statistics_cvss_rounded_scores", cvss_rounded_scores)
    insert_variable("statistics_cvss_categorized_scores", cvss_categorized_scores)

    # Vendors & Products statistics
    records = hook.get_records(sql=SQL_CVES_TOP_VENDORS)
    cves_top_vendors = {r[0]: r[1] for r in records}
    insert_variable("statistics_cves_top_vendors", cves_top_vendors)

    records = hook.get_records(sql=SQL_CVES_TOP_PRODUCTS)
    cves_top_products = {r[0]: r[1] for r in records}
    insert_variable("statistics_cves_top_products", cves_top_products)
