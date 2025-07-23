from datetime import datetime

from airflow import DAG
from airflow.models.param import Param

from includes.tasks.reports import generate_report_summaries


doc_md_DAG = """
The goal of this DAG is to generate summaries for each report.
"""


with DAG(
    "report_summaries",
    schedule="0 2 * * *",  # 2am UTC every day
    start_date=datetime(2025, 1, 1),
    catchup=False,
    max_active_runs=1,
    doc_md=doc_md_DAG,
) as dag:
    generate_report_summaries()
