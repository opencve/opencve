import logging
from unittest.mock import patch

import git
import pendulum
import pytest
from airflow.exceptions import AirflowException, AirflowSkipException

from includes.operators.parser_operator import ParserOperator


def test_parser_operator_unsupported_kind():
    ParserOperator(task_id="parse_test", kind="mitre")
    ParserOperator(task_id="parse_test", kind="nvd")

    with pytest.raises(AirflowException):
        ParserOperator(task_id="parse_test", kind="test")


def test_parser_operator_without_interval():
    operator = ParserOperator(task_id="parse_test", kind="mitre")
    day = pendulum.datetime(2023, 1, 1, tz="UTC")

    with pytest.raises(AirflowException):
        operator.execute({})
    with pytest.raises(AirflowException):
        operator.execute({"data_interval_start": day})
    with pytest.raises(AirflowException):
        operator.execute({"data_interval_end": day})


def test_parser_operator_interval_end_subtract_one_second():
    operator = ParserOperator(task_id="parse_test", kind="mitre")
    start = pendulum.datetime(2023, 1, 1, tz="UTC")
    end = start.add(hours=1)

    with patch.object(operator, "repo") as mock:
        with pytest.raises(AirflowSkipException):
            operator.execute({"data_interval_start": start, "data_interval_end": end})

        # The data_interval_end is 2023-01-01T01:00:00, but we need to call
        # the `iter_commits()` function with 2023-01-01T00:59:59
        expected_end = end.subtract(seconds=1)
        mock.iter_commits.assert_called_with(after=start, before=expected_end, reverse=True)


def test_parser_operator_no_commit_found():
    operator = ParserOperator(task_id="parse_test", kind="mitre")
    start = pendulum.datetime(2023, 1, 1, tz="UTC")
    end = start.add(hours=1)

    with patch.object(operator, "repo") as mock:
        mock.iter_commits.return_value = []
        with pytest.raises(AirflowSkipException):
            operator.execute({"data_interval_start": start, "data_interval_end": end})


def test_parser_operator_first_commit(cvelistv5_repo):
    operator = ParserOperator(task_id="parse_test", kind="mitre")

    # The only commit between 2023-01-01T00:00:00 and 2023-01-01T00:59:59
    # is the initial one, and an AirflowException is raided in this case.
    start = pendulum.datetime(2023, 1, 1, tz="UTC")
    end = start.add(hours=1)

    with patch.object(operator, "repo", cvelistv5_repo):
        with pytest.raises(AirflowException):
            operator.execute({"data_interval_start": start, "data_interval_end": end})


@patch.object(ParserOperator, "handle")
@pytest.mark.parametrize("hour,count", [(1, 2), (2, 1)])
def test_parser_operator_handler_calls_count(handler_mock, cvelistv5_repo, hour, count):
    operator = ParserOperator(task_id="parse_test", kind="mitre")

    # There are 2 commits between 2023-01-01T01:00:00 and 2023-01-01T01:59:59
    # and 1 commit between 2023-01-01T02:00:00 and 2023-01-01T02:59:59
    start = pendulum.datetime(2023, 1, 1, hour, tz="UTC")
    end = start.add(hours=1)

    with patch.object(operator, "repo", cvelistv5_repo):
        operator.execute({"data_interval_start": start, "data_interval_end": end})
    assert handler_mock.call_count == count


@patch("includes.handlers.mitre.MitreHandler")
def test_parser_operator_handler_call_mitre(handler_mock, cvelistv5_repo):
    operator = ParserOperator(task_id="parse_test", kind="mitre")

    # There is 1 commit between 2023-01-01T02:00:00 and 2023-01-01T02:59:59
    start = pendulum.datetime(2023, 1, 1, 2, tz="UTC")
    end = start.add(hours=1)

    with patch.object(operator, "repo", cvelistv5_repo):
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

