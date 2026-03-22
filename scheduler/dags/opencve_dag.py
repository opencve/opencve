import logging

import pendulum
from airflow.configuration import conf
from airflow.decorators import dag
from airflow.utils.task_group import TaskGroup
from includes.operators.fetch_operator import GitFetchOperator
from includes.operators.process_kb_operator import ProcessKbOperator
from includes.tasks.automations import (
    build_realtime_work_items,
    build_scheduled_report_content_hourly,
    build_scheduled_report_notification_payload,
    evaluate_scheduled_due_in_automation_timezone,
    execute_realtime_automation_actions,
    execute_scheduled_due_automation_actions,
    load_enabled_automations,
    upsert_scheduled_reports_and_entries,
)
from includes.tasks.statistics import compute_statistics
from includes.tasks.reports import collect_hourly_changes, resolve_subscriptions

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
    with TaskGroup(group_id="kb_refresh") as kb_refresh_group:
        git_fetch_tasks = [
            GitFetchOperator(task_id="FetchKb", kind="kb"),
            GitFetchOperator(task_id="FetchMitre", kind="mitre"),
            GitFetchOperator(task_id="FetchNvd", kind="nvd"),
            GitFetchOperator(task_id="FetchRedhat", kind="redhat"),
            GitFetchOperator(task_id="FetchVulnrichment", kind="vulnrichment"),
        ]
        (
            git_fetch_tasks
            >> ProcessKbOperator(task_id="ProcessKb")
            >> compute_statistics()
        )

    with TaskGroup(group_id="report_inputs") as report_inputs_group:
        (
            collect_hourly_changes()
            >> resolve_subscriptions()
            >> load_enabled_automations()
        )

    with TaskGroup(group_id="automation_processing") as automation_processing_group:
        with TaskGroup(group_id="realtime") as realtime_group:
            build_realtime_work = build_realtime_work_items()
            execute_realtime_actions = execute_realtime_automation_actions()
            build_realtime_work >> execute_realtime_actions

        with TaskGroup(group_id="scheduled") as scheduled_group:
            build_scheduled_hourly = build_scheduled_report_content_hourly()
            upsert_scheduled_reports = upsert_scheduled_reports_and_entries()
            evaluate_scheduled_due = evaluate_scheduled_due_in_automation_timezone()
            build_scheduled_notification_payload = (
                build_scheduled_report_notification_payload()
            )
            execute_scheduled_due_actions = execute_scheduled_due_automation_actions()

            build_scheduled_hourly >> upsert_scheduled_reports
            evaluate_scheduled_due >> build_scheduled_notification_payload
            upsert_scheduled_reports >> execute_scheduled_due_actions
            build_scheduled_notification_payload >> execute_scheduled_due_actions

    kb_refresh_group >> report_inputs_group >> automation_processing_group


opencve()
