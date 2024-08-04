import pytest
from unittest.mock import patch, PropertyMock

from airflow.exceptions import AirflowException
from includes.operators import KindOperator


def test_kind_operator():
    KindOperator(task_id="test_operator", kind="kb")
    KindOperator(task_id="test_operator", kind="mitre")
    KindOperator(task_id="test_operator", kind="nvd")
    KindOperator(task_id="test_operator", kind="redhat")
    KindOperator(task_id="test_operator", kind="vulnrichment")

    message = "Kind foo is not supported"
    with pytest.raises(AirflowException, match=message):
        KindOperator(task_id="test_operator", kind="foo")


@pytest.mark.parametrize("kind", ["kb", "mitre", "nvd", "redhat", "vulnrichment"])
@patch("includes.operators.KindOperator.REPOS_PATH", new_callable=PropertyMock)
def test_kind_operator_get_repo_path(mock, kind):
    mock.return_value = {kind: f"/path/to/{kind}"}

    operator = KindOperator(task_id="test_operator", kind=kind)
    assert str(operator.get_repo_path()) == f"/path/to/{kind}"


def test_kind_operator_unsupported_kind():
    message = "Kind test is not supported"
    with pytest.raises(AirflowException, match=message):
        KindOperator(task_id="test_operator", kind="test")
