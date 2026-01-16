import pendulum
from airflow import DAG
from airflow.configuration import conf
from airflow.operators.python import PythonOperator

from includes.tasks.reports import clean_reports


doc_md_DAG = """
This DAG deletes expired reports and their related changes.
"""

# The catchup is set to False because this cleanup is idempotent and daily.
start_date = pendulum.from_format(conf.get("opencve", "start_date"), "YYYY-MM-DD")

with DAG(
    "clean_reports",
    schedule="0 2 * * *",  # 2am UTC every day
    start_date=start_date,
    catchup=False,
    max_active_runs=1,
    doc_md=doc_md_DAG,
) as dag:
    PythonOperator(task_id="clean_reports", python_callable=clean_reports)
