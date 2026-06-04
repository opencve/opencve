import logging

import pendulum
from airflow.configuration import conf
from airflow.decorators import dag
from airflow.utils.task_group import TaskGroup
from includes.operators.fetch_operator import GitFetchOperator
from includes.operators.process_kb_operator import ProcessKbOperator
from includes.tasks.automations import (
    build_alert_work_items,
    build_report_content_hourly,
    build_report_notification_payload,
    evaluate_report_due_in_automation_timezone,
    execute_alert_automation_actions,
    execute_report_due_automation_actions,
    list_alert_action_chunk_indices,
    load_enabled_automations,
    upsert_report_content_and_entries,
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

    with TaskGroup(group_id="report_inputs") as report_inputs_group:
        (
            collect_hourly_changes()
            >> resolve_subscriptions()
            >> load_enabled_automations()
        )

    with TaskGroup(group_id="automation_processing") as automation_processing_group:
        with TaskGroup(group_id="alert") as alert_group:
            build_alert_work = build_alert_work_items()
            alert_chunk_indices = list_alert_action_chunk_indices()
            execute_alert_actions = execute_alert_automation_actions.expand(
                chunk_index=alert_chunk_indices
            )
            build_alert_work >> alert_chunk_indices >> execute_alert_actions

        with TaskGroup(group_id="report") as report_group:
            build_report_hourly = build_report_content_hourly()
            upsert_report_content = upsert_report_content_and_entries()
            evaluate_report_due = evaluate_report_due_in_automation_timezone()
            build_report_notification = build_report_notification_payload()
            execute_report_due_actions = execute_report_due_automation_actions()

            build_report_hourly >> upsert_report_content
            evaluate_report_due >> build_report_notification
            upsert_report_content >> execute_report_due_actions
            build_report_notification >> execute_report_due_actions

    kb_refresh_group >> report_inputs_group >> automation_processing_group


opencve()
