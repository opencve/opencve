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
    assert "kb_refresh.ProcessKb" in task_ids
    assert "kb_refresh.ComputeStatistics" in task_ids
    assert "report_inputs.CollectHourlyChanges" in task_ids
    assert "report_inputs.ResolveSubscriptions" in task_ids
    assert "report_inputs.LoadEnabledAutomations" in task_ids
    assert (
        "automation_processing.scheduled.BuildScheduledReportContentHourly" in task_ids
    )
    assert (
        "automation_processing.scheduled.UpsertScheduledReportsAndEntries" in task_ids
    )
    assert (
        "automation_processing.scheduled.EvaluateScheduledDueInAutomationTimezone"
        in task_ids
    )
    assert (
        "automation_processing.scheduled.BuildScheduledReportNotificationPayload"
        in task_ids
    )
    assert "automation_processing.realtime.BuildRealtimeWorkItems" in task_ids
    assert "automation_processing.realtime.ExecuteRealtimeActions" in task_ids
    assert (
        "automation_processing.scheduled.SendScheduledReportNotificationsDailyOrWeekly"
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
