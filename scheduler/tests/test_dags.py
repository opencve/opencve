import pytest

from airflow.models import DagBag


@pytest.fixture()
def dagbag():
    return DagBag()


def test_dag_loaded(dagbag):
    dag = dagbag.get_dag(dag_id="opencve")
    assert dagbag.import_errors == {}
    assert dag is not None
    assert len(dag.tasks) == 12
    tasks = sorted([t.task_id for t in dag.tasks])
    assert tasks == [
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


def test_dag_structure(dagbag):
    dag = dagbag.get_dag(dag_id="opencve")
    structure = {
        "cves.fetch_kb": ["cves.process_kb"],
        "cves.fetch_mitre": ["cves.process_kb"],
        "cves.fetch_nvd": ["cves.process_kb"],
        "cves.fetch_redhat": ["cves.process_kb"],
        "cves.fetch_vulnrichment": ["cves.process_kb"],
        "cves.process_kb": ["reports.list_changes"],
        "reports.list_changes": ["reports.list_subscriptions"],
        "reports.list_subscriptions": [
            "reports.populate_reports",
            "reports.prepare_notifications",
        ],
        "reports.populate_reports": ["notifications.make_notifications_chunks"],
        "reports.prepare_notifications": ["notifications.make_notifications_chunks"],
        "notifications.make_notifications_chunks": ["notifications.send_notifications"],
        "notifications.send_notifications": [],
    }

    assert dag.task_dict.keys() == structure.keys()
    for task_id, downstream_list in structure.items():
        assert dag.has_task(task_id)
        task = dag.get_task(task_id)
        assert task.downstream_task_ids == set(downstream_list)
