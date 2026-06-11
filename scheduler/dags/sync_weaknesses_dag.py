from datetime import timedelta

import pendulum
from airflow.configuration import conf
from airflow import DAG

from includes.tasks.weaknesses import sync_weaknesses

doc_md_DAG = """
The goal of this DAG is to synchronize weakness data from MITRE.
"""


start_date = pendulum.from_format(
    conf.get("opencve", "start_date_sync_weaknesses", fallback="2026-06-08"),
    "YYYY-MM-DD",
)

with DAG(
    "sync_weaknesses",
    schedule="0 3 * * 1",  # 3am UTC every Monday
    start_date=start_date,
    catchup=False,
    max_active_runs=1,
    doc_md=doc_md_DAG,
    default_args={
        "retries": 3,
        "retry_delay": timedelta(seconds=10),
    },
) as dag:
    sync_weaknesses()
