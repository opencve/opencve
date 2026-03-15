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
    assert len(dag.tasks) == 15
    tasks = sorted([t.task_id for t in dag.tasks])
    assert tasks == [
        "automations.execute_automation_actions",
        "automations.make_automations_chunks",
        "cves.compute_statistics",
        "cves.fetch_kb",
        "cves.fetch_mitre",
        "cves.fetch_nvd",
        "cves.fetch_redhat",
        "cves.fetch_vulnrichment",
        "cves.process_kb",
        "reports.prepare_automations",
        "reports.list_changes",
        "reports.list_subscriptions",
        "reports.populate_reports",
        "should_create_reports",
        "should_launch_automations",
    ]


def test_dag_check_smtp_loaded(dagbag):
    dag = dagbag.get_dag(dag_id="check_smtp")
    assert dagbag.import_errors == {}
    assert dag is not None
    assert len(dag.tasks) == 1
    tasks = [t.task_id for t in dag.tasks]
    assert tasks == ["run"]


@pytest.mark.parametrize(
    "task_id,variable_name,variable_value,expected_result",
    [
        ("should_create_reports", "create_reports", "true", True),
        ("should_create_reports", "create_reports", "false", False),
        ("should_create_reports", "create_reports", "other", False),
        ("should_launch_automations", "launch_automations", "true", True),
        ("should_launch_automations", "launch_automations", "false", False),
        (
            "should_launch_automations",
            "launch_automations",
            "other",
            False,
        ),
    ],
)
@patch("airflow.models.Variable.get")
def test_shortcircuit_operators_behavior(
    mock_variable_get, dagbag, task_id, variable_name, variable_value, expected_result
):
    """Test ShortCircuitOperator behavior with different variable values"""
    mock_variable_get.return_value = variable_value

    dag = dagbag.get_dag(dag_id="opencve")
    task = dag.get_task(task_id)
    result = task.python_callable()

    assert result is expected_result
    mock_variable_get.assert_called_once_with(variable_name, default_var="true")


def test_shortcircuit_task_dependencies(dagbag):
    """Test that task dependencies are correct for ShortCircuitOperator tasks"""
    dag = dagbag.get_dag(dag_id="opencve")
    should_create_reports = dag.get_task("should_create_reports")
    should_launch_automations = dag.get_task("should_launch_automations")

    # Verify should_create_reports has correct upstream dependencies
    upstream_task_ids = [t.task_id for t in should_create_reports.upstream_list]
    assert "cves.compute_statistics" in upstream_task_ids

    # Verify should_launch_automations has correct upstream dependencies
    upstream_task_ids = [t.task_id for t in should_launch_automations.upstream_list]
    assert "reports.prepare_automations" in upstream_task_ids
    assert "reports.populate_reports" in upstream_task_ids

    # Verify downstream tasks are correct
    downstream_task_ids = [t.task_id for t in should_create_reports.downstream_list]
    assert "reports.list_changes" in downstream_task_ids

    downstream_task_ids = [t.task_id for t in should_launch_automations.downstream_list]
    assert "automations.make_automations_chunks" in downstream_task_ids
