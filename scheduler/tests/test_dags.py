import pytest

from airflow.models import DagBag


@pytest.fixture()
def dagbag():
    return DagBag()


def test_dag_loaded(dagbag):
    dag = dagbag.get_dag(dag_id="updater")
    assert dagbag.import_errors == {}
    assert dag is not None
    assert len(dag.tasks) == 4


def test_dag_structure(dagbag):
    dag = dagbag.get_dag(dag_id="updater")
    structure = {
        "fetchers.fetch_mitre": ["parsers.parse_mitre", "parsers.parse_nvd"],
        "fetchers.fetch_nvd": ["parsers.parse_mitre", "parsers.parse_nvd"],
        "parsers.parse_mitre": [],
        "parsers.parse_nvd": [],
    }

    assert dag.task_dict.keys() == structure.keys()
    for task_id, downstream_list in structure.items():
        assert dag.has_task(task_id)
        task = dag.get_task(task_id)
        assert task.downstream_task_ids == set(downstream_list)
