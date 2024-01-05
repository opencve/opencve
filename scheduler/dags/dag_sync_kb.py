import logging

import pendulum
from airflow.decorators import dag
from airflow.utils.task_group import TaskGroup

from includes.operators.fetch_operator import FetchOperator
from includes.operators.insert_operator import InsertOperator
from includes.tasks import list_projects, populate_reports, send_notifications

logger = logging.getLogger(__name__)


@dag(
    schedule="0 * * * *",
    start_date=pendulum.datetime(2023, 1, 1, tz="UTC"),
    catchup=False,
    max_active_runs=1,
)
def opencve():
    with TaskGroup(group_id="fetchers") as fetch_group:
        _ = [
            FetchOperator(task_id="fetch_kb", kind="kb"),
            FetchOperator(task_id="fetch_mitre", kind="mitre"),
            FetchOperator(task_id="fetch_nvd", kind="nvd"),
        ]

    insert_changes_task = InsertOperator(task_id="insert_changes")
    list_projects_task = list_projects()
    populate_reports_task = populate_reports()
    send_notifications_task = send_notifications()

    (fetch_group >> insert_changes_task >> list_projects_task >> populate_reports_task >> send_notifications_task)


opencve()
