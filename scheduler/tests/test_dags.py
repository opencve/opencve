import pytest

from airflow.models import DagBag


@pytest.fixture()
def dagbag():
    return DagBag()


def test_dag_opencve_loaded(dagbag):
    dag = dagbag.get_dag(dag_id="opencve")
    assert dagbag.import_errors == {}
    assert dag is not None
    assert len(dag.tasks) == 13
    tasks = sorted([t.task_id for t in dag.tasks])
    assert tasks == [
        "cves.compute_statistics",
        "cves.fetch_kb",
        "cves.fetch_mitre",
        "cves.fetch_nvd",
        "cves.fetch_redhat",
        "cves.fetch_vulnrichment",
        "cves.process_kb",
        "notifications.make_notifications_chunks",
        "notifications.send_notifications",
        "reports.list_changes",
        "reports.list_subscriptions",
        "reports.populate_reports",
        "reports.prepare_notifications",
    ]


def test_dag_check_smtp_loaded(dagbag):
    dag = dagbag.get_dag(dag_id="check_smtp")
    assert dagbag.import_errors == {}
    assert dag is not None
    assert len(dag.tasks) == 1
    tasks = [t.task_id for t in dag.tasks]
    assert tasks == ["run"]
