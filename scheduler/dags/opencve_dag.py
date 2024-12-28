import logging

import pendulum
from airflow.configuration import conf
from airflow.decorators import dag
from airflow.utils.task_group import TaskGroup
from includes.operators.fetch_operator import GitFetchOperator
from includes.operators.process_kb_operator import ProcessKbOperator
from includes.tasks.notifications import (
    make_notifications_chunks,
    prepare_notifications,
    send_notifications,
)
from includes.tasks.statistics import compute_statistics
from includes.tasks.reports import list_changes, list_subscriptions, populate_reports

logger = logging.getLogger(__name__)

# The catchup is set to True, so we allow the user to update his start_date
# value to match the installation date of his own OpenCVE instance.
start_date = pendulum.from_format(conf.get("opencve", "start_date"), "YYYY-MM-DD")


@dag(
    schedule="0 * * * *",
    start_date=start_date,
    catchup=True,
    max_active_runs=1,
)
def opencve():
    with TaskGroup(group_id="cves") as cves_group:
        git_fetch_tasks = [
            GitFetchOperator(task_id="fetch_kb", kind="kb"),
            GitFetchOperator(task_id="fetch_mitre", kind="mitre"),
            GitFetchOperator(task_id="fetch_nvd", kind="nvd"),
            GitFetchOperator(task_id="fetch_redhat", kind="redhat"),
            GitFetchOperator(task_id="fetch_vulnrichment", kind="vulnrichment"),
        ]
        (
            git_fetch_tasks
            >> ProcessKbOperator(task_id="process_kb")
            >> compute_statistics()
        )

    with TaskGroup(group_id="reports") as reports_group:
        (
            list_changes()
            >> list_subscriptions()
            >> [populate_reports(), prepare_notifications()]
        )

    with TaskGroup(group_id="notifications") as notifications_group:
        send_notifications.expand(notifications=make_notifications_chunks())

    cves_group >> reports_group >> notifications_group


opencve()
