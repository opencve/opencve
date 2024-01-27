import logging

import pendulum
from airflow.decorators import dag
from airflow.utils.task_group import TaskGroup

from includes.operators.fetch_operator import GitPullOperator
from includes.operators.insert_operator import ProcessKbOperator
from includes.tasks.reports import list_changes, list_subscriptions, populate_reports
from includes.tasks.notifications import list_notifications, send_notifications, make_notifications_chunks

logger = logging.getLogger(__name__)


@dag(
    schedule="0 * * * *",
    start_date=pendulum.datetime(2023, 1, 1, tz="UTC"),
    catchup=False,
    max_active_runs=1,
)
def opencve():
    with TaskGroup(group_id="cves") as cves_group:
        git_pull_tasks = [
            GitPullOperator(task_id="pull_kb", kind="kb"),
            GitPullOperator(task_id="pull_mitre", kind="mitre"),
            GitPullOperator(task_id="pull_nvd", kind="nvd"),
        ]
        git_pull_tasks >> ProcessKbOperator(task_id="process_kb")

    with TaskGroup(group_id="reports") as reports_group:
        list_changes() >> list_subscriptions() >> populate_reports()

    with TaskGroup(group_id="notifications") as notifications_group:
        list_notifications() >> send_notifications.expand(notifications=make_notifications_chunks())

    cves_group >> reports_group >> notifications_group


opencve()
