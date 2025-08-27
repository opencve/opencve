from datetime import datetime

import pendulum
from airflow.configuration import conf
from airflow import DAG

from includes.tasks.reports import summarize_reports


doc_md_DAG = """
The goal of this DAG is to generate summaries for each report using a LLM.
"""

# The catchup is set to True, so we allow the user to update his start_date
# value to match the installation date of his own OpenCVE instance.
start_date = pendulum.from_format(
    conf.get("opencve", "start_date_summarize_reports"), "YYYY-MM-DD"
)


with DAG(
    "summarize_reports",
    schedule="0 2 * * *",  # 2am UTC every day
    start_date=start_date,
    catchup=True,
    max_active_runs=1,
    doc_md=doc_md_DAG,
) as dag:
    summarize_reports()
