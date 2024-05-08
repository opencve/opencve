import logging
from unittest.mock import patch, PropertyMock

import git
import pendulum
import pytest
from airflow.exceptions import AirflowException, AirflowSkipException

from includes.operators import KindOperator
from includes.operators.fetcher_operator import FetcherOperator
from includes.operators.parser_operator import ParserOperator


# includes.operators.parser_operator.ParserOperator


def test_kind_operator_unsupported_kind():
    KindOperator(task_id="test_operator", kind="mitre")
    KindOperator(task_id="test_operator", kind="nvd")
    KindOperator(task_id="test_operator", kind="redhat")

    message = "Kind test is not supported"
    with pytest.raises(AirflowException, match=message):
        KindOperator(task_id="test_operator", kind="test")


def test_kind_operator_get_repo_path():
    operator = KindOperator(task_id="test_operator", kind="mitre")
    with patch.dict("os.environ", AIRFLOW_VAR_MITRE_REPO_PATH="/path/to/mitre"):
        assert str(operator.get_repo_path()) == "/path/to/mitre"

    operator = KindOperator(task_id="test_operator", kind="nvd")
    with patch.dict("os.environ", AIRFLOW_VAR_NVD_REPO_PATH="/path/to/nvd"):
        assert str(operator.get_repo_path()) == "/path/to/nvd"

    operator = KindOperator(task_id="test_operator", kind="redhat")
    with patch.dict("os.environ", AIRFLOW_VAR_REDHAT_REPO_PATH="/path/to/redhat"):
        assert str(operator.get_repo_path()) == "/path/to/redhat"

    operator = KindOperator(task_id="test_operator", kind="mitre")
    message = "Variable mitre_repo_path not found"
    with pytest.raises(AirflowException, match=message):
        operator.get_repo_path()


# includes.operators.parser_operator.ParserOperator


@patch.object(ParserOperator, "handle")
def test_parser_operator_without_interval(_mock_handle, mitre_repo):
    operator = ParserOperator(task_id="parse_test", kind="mitre")
    day = pendulum.datetime(2023, 1, 1, 1, tz="UTC")

    with patch.dict(
        "os.environ", AIRFLOW_VAR_MITRE_REPO_PATH=str(mitre_repo.repo_path)
    ):
        message = "Start and end intervals must be set"
        with pytest.raises(AirflowException, match=message):
            operator.execute({})
        with pytest.raises(AirflowException, match=message):
            operator.execute({"data_interval_start": day})
        with pytest.raises(AirflowException, match=message):
            operator.execute({"data_interval_end": day})

        # No exception
        operator.execute(
            {"data_interval_start": day, "data_interval_end": day.add(hours=1)}
        )


@patch("git.Repo")
def test_parser_operator_interval_end_subtract_one_second(mock_repo, mitre_repo):
    operator = ParserOperator(task_id="parse_test", kind="mitre")
    start = pendulum.datetime(2023, 1, 1, tz="UTC")
    end = start.add(hours=1)

    with patch.dict(
        "os.environ", AIRFLOW_VAR_MITRE_REPO_PATH=str(mitre_repo.repo_path)
    ):
        with pytest.raises(AirflowSkipException):
            operator.execute({"data_interval_start": start, "data_interval_end": end})

    # The data_interval_end is 2023-01-01T01:00:00, but we need to call
    # the `iter_commits()` function with 2023-01-01T00:59:59
    expected_end = end.subtract(seconds=1)
    mock_repo().iter_commits.assert_called_with(
        after=start, before=expected_end, reverse=True
    )


@patch("git.Repo")
def test_parser_operator_no_commit_found(mock_repo, mitre_repo):
    operator = ParserOperator(task_id="parse_test", kind="mitre")
    start = pendulum.datetime(2023, 1, 1, tz="UTC")
    end = start.add(hours=1)

    with patch.dict(
        "os.environ", AIRFLOW_VAR_MITRE_REPO_PATH=str(mitre_repo.repo_path)
    ):
        with pytest.raises(AirflowSkipException, match="No commit found"):
            operator.execute({"data_interval_start": start, "data_interval_end": end})
        mock_repo.iter_commits.return_value = []


def test_parser_operator_first_commit(mitre_repo):
    operator = ParserOperator(task_id="parse_test", kind="mitre")

    # The only commit between 2023-01-01T00:00:00 and 2023-01-01T00:59:59
    # is the initial one, and an AirflowException is raided in this case.
    start = pendulum.datetime(2023, 1, 1, tz="UTC")
    end = start.add(hours=1)

    with patch.dict(
        "os.environ", AIRFLOW_VAR_MITRE_REPO_PATH=str(mitre_repo.repo_path)
    ):
        message = "The first commit can't be used by the scheduler"
        with pytest.raises(AirflowException, match=message):
            operator.execute({"data_interval_start": start, "data_interval_end": end})


@patch.object(ParserOperator, "handle")
@pytest.mark.parametrize("hour,count", [(1, 2), (2, 1)])
def test_parser_operator_handler_calls_count(handler_mock, mitre_repo, hour, count):
    operator = ParserOperator(task_id="parse_test", kind="mitre")

    # There are 2 commits between 2023-01-01T01:00:00 and 2023-01-01T01:59:59
    # and 1 commit between 2023-01-01T02:00:00 and 2023-01-01T02:59:59
    start = pendulum.datetime(2023, 1, 1, hour, tz="UTC")
    end = start.add(hours=1)

    with patch.dict(
        "os.environ", AIRFLOW_VAR_MITRE_REPO_PATH=str(mitre_repo.repo_path)
    ):
        operator.execute({"data_interval_start": start, "data_interval_end": end})
    assert handler_mock.call_count == count


@patch("includes.handlers.mitre.MitreHandler")
def test_parser_operator_handler_call_mitre_handler_diffs(handler_mock, mitre_repo):
    operator = ParserOperator(task_id="parse_test", kind="mitre")

    # There is 1 commit between 2023-01-01T02:00:00 and 2023-01-01T02:59:59
    start = pendulum.datetime(2023, 1, 1, 2, tz="UTC")
    end = start.add(hours=1)

    with patch.dict(
        "os.environ", AIRFLOW_VAR_MITRE_REPO_PATH=str(mitre_repo.repo_path)
    ):
        operator.execute({"data_interval_start": start, "data_interval_end": end})

    # There are 2 diffs in this commit
    assert handler_mock.call_count == 2

    # class DiffHandler:
    #     def __init__(self, logger, commit, diff):
    for diff_idx in range(2):
        args = handler_mock.call_args_list[diff_idx].args
        assert type(args[0]) == logging.Logger
        assert type(args[1]) == git.Commit
        assert type(args[2]) == git.diff.Diff

        # Commit date is `Sun Jan 1 02:10:00 2023 +0000`
        assert args[1].committed_date == 1672539000


# includes.operators.parser_operator.ParserOperator


def test_fetcher_operator_repo_path_not_exists(mitre_repo):
    operator = FetcherOperator(task_id="fetch_test", kind="mitre")
    with patch.dict("os.environ", AIRFLOW_VAR_MITRE_REPO_PATH="."):
        message = r"Repository .* seems empty or broken"
        with pytest.raises(AirflowException, match=message):
            operator.execute({})


@patch("git.Repo.remotes", new_callable=PropertyMock)
def test_fetcher_operator_repo_no_remotes(mock, mitre_repo):
    mock.return_value = []
    operator = FetcherOperator(task_id="fetch_test", kind="mitre")

    with patch.dict(
        "os.environ", AIRFLOW_VAR_MITRE_REPO_PATH=str(mitre_repo.repo_path)
    ):
        message = r"Repository .* has no remote"
        with pytest.raises(AirflowException, match=message):
            operator.execute({})
