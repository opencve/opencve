from datetime import timedelta

import pendulum
from airflow import DAG
from airflow.configuration import conf
from airflow.sensors.external_task import ExternalTaskSensor

from includes.tasks.report_notifications import send_report_notifications

doc_md_DAG = """
This DAG sends daily AI-generated security report emails to users who have
configured a 'report' notification on their project. It runs at 6 AM UTC,
after the summarize_reports DAG (which runs at 2 AM UTC) has completed.
"""

start_date = pendulum.from_format(
    conf.get("opencve", "start_date_summarize_reports"), "YYYY-MM-DD"
)

with DAG(
    "send_reports",
    schedule="0 6 * * *",
    start_date=start_date,
    catchup=True,
    max_active_runs=1,
    doc_md=doc_md_DAG,
    default_args={
        "retries": 3,
        "retry_delay": timedelta(seconds=10),
    },
) as dag:

    wait_for_summarize = ExternalTaskSensor(
        task_id="wait_for_summarize_reports",
        external_dag_id="summarize_reports",
        external_task_id="summarize_reports",
        execution_delta=timedelta(hours=4),
        timeout=3600,
        mode="reschedule",
        allowed_states=["success", "skipped"],
        poke_interval=60,
    )

    wait_for_summarize >> send_report_notifications()
