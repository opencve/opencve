import pytest
from unittest.mock import patch

from airflow.models import DagBag


@pytest.fixture()
def dagbag():
    return DagBag()


def test_dag_opencve_loaded(dagbag):
    dag = dagbag.get_dag(dag_id="opencve")
    assert dagbag.import_errors == {}
    assert dag is not None
    task_ids = {t.task_id for t in dag.tasks}
    # Core tasks still exist
    assert "kb_refresh.process_kb" in task_ids
    assert "kb_refresh.compute_statistics" in task_ids
    assert "report_inputs.collect_hourly_changes" in task_ids
    assert "report_inputs.resolve_subscriptions" in task_ids
    assert "report_inputs.load_enabled_automations" in task_ids
    assert "automation_processing.report.build_report_content_hourly" in task_ids
    assert "automation_processing.report.upsert_report_content_and_entries" in task_ids
    assert (
        "automation_processing.report.evaluate_report_due_in_automation_timezone"
        in task_ids
    )
    assert "automation_processing.report.build_report_notification_payload" in task_ids
    assert "automation_processing.alert.build_alert_work_items" in task_ids
    assert "automation_processing.alert.list_alert_action_chunk_indices" in task_ids
    assert "automation_processing.alert.execute_alert_actions" in task_ids
    assert (
        "automation_processing.report.send_report_notifications_daily_or_weekly"
        in task_ids
    )
    # Short-circuit guards removed
    assert "should_create_reports" not in task_ids
    assert "should_launch_automations" not in task_ids


def test_dag_check_smtp_loaded(dagbag):
    dag = dagbag.get_dag(dag_id="check_smtp")
    assert dagbag.import_errors == {}
    assert dag is not None
    assert len(dag.tasks) == 1
    tasks = [t.task_id for t in dag.tasks]
    assert tasks == ["run"]


def test_shortcircuit_removed(dagbag):
    """Sanity check: removed guard tasks."""
    dag = dagbag.get_dag(dag_id="opencve")
    task_ids = {t.task_id for t in dag.tasks}
    assert "should_create_reports" not in task_ids
    assert "should_launch_automations" not in task_ids
