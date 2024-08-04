from unittest.mock import patch, PropertyMock

import pytest
from airflow.exceptions import AirflowException

from utils import TestRepo
from includes.operators.fetch_operator import GitFetchOperator


@patch("includes.operators.KindOperator.REPOS_PATH", new_callable=PropertyMock)
def test_fetch_operator_repo_path_not_exists(mock):
    mock.return_value = {"mitre": "/foo/bar"}
    operator = GitFetchOperator(task_id="fetch_test", kind="mitre")
    message = "Repository /foo/bar seems empty or broken"
    with pytest.raises(AirflowException, match=message):
        operator.execute({})


@patch("git.Repo.remotes", new_callable=PropertyMock)
def test_fetch_operator_repo_no_remotes(mock, tests_path, tmp_path_factory):
    mock.return_value = []

    repo = TestRepo("", tests_path, tmp_path_factory)
    with patch(
        "includes.operators.KindOperator.REPOS_PATH", new_callable=PropertyMock
    ) as mock_paths:
        mock_paths.return_value = {"mitre": repo.repo_path}

        operator = GitFetchOperator(task_id="fetch_test", kind="mitre")

        message = r"Repository .* has no remote"
        with pytest.raises(AirflowException, match=message):
            operator.execute({})
