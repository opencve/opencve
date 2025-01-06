from datetime import datetime

from airflow import DAG
from airflow.models.param import Param

from includes.tasks.smtp import run


doc_md_DAG = """
The goal of this DAG is to send an email to verify the SMTP configuration.
"""


with DAG(
    "check_smtp",
    schedule=None,
    start_date=datetime(2025, 1, 1),
    max_active_runs=1,
    doc_md=doc_md_DAG,
    params={"email": Param("airflow@example.com", type="string")},
) as dag:
    run()
