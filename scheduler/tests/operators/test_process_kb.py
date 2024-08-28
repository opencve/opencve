from datetime import datetime
from unittest.mock import patch

import pendulum
import pytest
from airflow.exceptions import AirflowException

from utils import TestRepo
from includes.operators.process_kb_operator import ProcessKbOperator, PostgresHook


@patch("includes.utils.Repo")
def test_process_kb_operator_without_interval(mock_git):
    operator = ProcessKbOperator(task_id="parse_test")
    day = pendulum.datetime(2024, 1, 1, 1, tz="UTC")

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


@patch("includes.utils.Repo")
def test_process_kb_operator_interval_end_subtract_one_second(mock_repo):
    operator = ProcessKbOperator(task_id="parse_test")
    start = pendulum.datetime(2024, 1, 1, tz="UTC")
    end = start.add(hours=1)
    operator.execute({"data_interval_start": start, "data_interval_end": end})

    # The data_interval_end is 2024-01-01T01:00:00, but we need to call
    # the `iter_commits()` function with 2024-01-01T00:59:59
    expected_end = end.subtract(seconds=1)

    mock_repo().iter_commits.assert_called_with(
        after=start, before=expected_end, reverse=True
    )


@patch.object(ProcessKbOperator, "process_commit")
def test_process_kb_operator_find_commits(_, caplog, tests_path, tmp_path_factory):
    repo = TestRepo("example", tests_path, tmp_path_factory)
    repo.commit(["a/"], hour=1, minute=00)
    repo.commit(["b/"], hour=2, minute=00)
    repo.commit(["c/"], hour=2, minute=30)

    with patch("includes.utils.KB_LOCAL_REPO", repo.repo_path):

        # No commit between 12:00 and 12:59:59
        operator = ProcessKbOperator(task_id="parse_test")
        operator.execute(
            {
                "data_interval_start": pendulum.datetime(2024, 1, 1, 12, tz="UTC"),
                "data_interval_end": pendulum.datetime(2024, 1, 1, 13, tz="UTC"),
            }
        )
        assert "No commit found" in caplog.text

        # One commit between 01:00 and 01:59:59
        operator = ProcessKbOperator(task_id="parse_test")
        operator.execute(
            {
                "data_interval_start": pendulum.datetime(2024, 1, 1, 1, tz="UTC"),
                "data_interval_end": pendulum.datetime(2024, 1, 1, 2, tz="UTC"),
            }
        )
        assert "Found 1 commit(s)" in caplog.text

        # Two commits between 02:00 and 02:59:59
        operator = ProcessKbOperator(task_id="parse_test")
        operator.execute(
            {
                "data_interval_start": pendulum.datetime(2024, 1, 1, 2, tz="UTC"),
                "data_interval_end": pendulum.datetime(2024, 1, 1, 3, tz="UTC"),
            }
        )
        assert "Found 2 commit(s)" in caplog.text


@patch.object(ProcessKbOperator, "process_commit")
def test_process_kb_operator_first_commit(
    mock_process_commit, caplog, tests_path, tmp_path_factory
):
    repo = TestRepo("example", tests_path, tmp_path_factory)

    # The only commit between 01:00 and 01:59:59 is the initial one
    with patch("includes.utils.KB_LOCAL_REPO", repo.repo_path):
        operator = ProcessKbOperator(task_id="parse_test")
        operator.execute(
            {
                "data_interval_start": pendulum.datetime(2024, 1, 1, 0, tz="UTC"),
                "data_interval_end": pendulum.datetime(2024, 1, 1, 1, tz="UTC"),
            }
        )
        mock_process_commit.assert_not_called()


@patch.object(ProcessKbOperator, "process_commit")
@pytest.mark.parametrize("hour,count", [(1, 3), (2, 1)])
def test_process_kb_operator_process_commit_call_count(
    mock_process_commit, tests_path, tmp_path_factory, hour, count
):
    repo = TestRepo("example", tests_path, tmp_path_factory)
    repo.commit(["a/"], hour=1, minute=00)
    repo.commit(["b/"], hour=1, minute=15)
    repo.commit(["c/"], hour=1, minute=50)
    repo.commit(["d/"], hour=2, minute=30)

    with patch("includes.utils.KB_LOCAL_REPO", repo.repo_path):
        operator = ProcessKbOperator(task_id="parse_test")

        # There are 3 commits between 01:00 and 01:59:59
        # and 1 commit between 02:00 and 02:59:59
        operator.execute(
            {
                "data_interval_start": pendulum.datetime(2024, 1, 1, hour, tz="UTC"),
                "data_interval_end": pendulum.datetime(2024, 1, 1, hour + 1, tz="UTC"),
            }
        )
        assert mock_process_commit.call_count == count


@patch.object(PostgresHook, "run")
@patch.object(ProcessKbOperator, "process_diff")
@pytest.mark.parametrize("hour,count", [(1, 3), (2, 2)])
def test_process_kb_operator_process_diff_call_count(
    mock_process_diff, mock_hook, tests_path, tmp_path_factory, hour, count
):
    mock_process_diff.return_value = {"cve": "CVE-2024-1234", "changes": []}

    repo = TestRepo("example", tests_path, tmp_path_factory)
    repo.commit(["a/"], hour=1, minute=00)
    repo.commit(["b/"], hour=1, minute=15)
    repo.commit(["c/"], hour=1, minute=50)
    repo.commit(["d/"], hour=2, minute=30)

    with patch("includes.utils.KB_LOCAL_REPO", repo.repo_path):
        operator = ProcessKbOperator(task_id="parse_test")

        # There are 3 commits with 1 diff (so 3 diffs) between 01:00 and 01:59:59
        # and 1 commit with 2 diffs (so 2 diffs) between 02:00 and 02:59:59
        operator.execute(
            {
                "data_interval_start": pendulum.datetime(2024, 1, 1, hour, tz="UTC"),
                "data_interval_end": pendulum.datetime(2024, 1, 1, hour + 1, tz="UTC"),
            }
        )
        assert mock_process_diff.call_count == count
        assert mock_hook.call_count == count


@pytest.mark.web_db
def test_process_kb_operator_create_cve(tests_path, tmp_path_factory, web_pg_hook):
    repo = TestRepo("multiple-changes", tests_path, tmp_path_factory)
    repo.commit(["2024/CVE-2024-6962.v1.json"], hour=1, minute=00)

    with patch("includes.utils.KB_LOCAL_REPO", repo.repo_path):
        operator = ProcessKbOperator(task_id="parse_test")
        operator.execute(
            {
                "data_interval_start": pendulum.datetime(2024, 1, 1, 1, tz="UTC"),
                "data_interval_end": pendulum.datetime(2024, 1, 1, 2, tz="UTC"),
            }
        )

    # Compare the CVE data
    db_data = web_pg_hook.get_records(
        "SELECT id, cve_id, created_at, updated_at, title,description, vendors, weaknesses, metrics "
        "FROM opencve_cves;"
    )

    assert db_data[0][1] == "CVE-2024-6962"
    assert db_data[0][2] == datetime.fromisoformat("2024-01-01T00:00:00+00:00")
    assert db_data[0][3] == datetime.fromisoformat("2024-01-01T00:00:00+00:00")
    assert db_data[0][4] == "Tenda O3 formQosSet stack-based overflow"
    assert (
        db_data[0][5]
        == "A vulnerability classified as critical was found in Tenda O3 1.0.0.10. This vulnerability affects the function formQosSet. The manipulation of the argument remark/ipRange/upSpeed/downSpeed/enable leads to stack-based buffer overflow. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-272116. NOTE: The vendor was contacted early about this disclosure but did not respond in any way."
    )
    assert db_data[0][6] == ["foo", "foo$PRODUCT$bar"]
    assert db_data[0][7] == ["CWE-121"]
    assert db_data[0][8] == {
        "cvssV2_0": {
            "data": {"score": 9, "vector": "AV:N/AC:L/Au:S/C:C/I:C/A:C"},
            "provider": "mitre",
        },
        "cvssV3_0": {
            "data": {
                "score": 8.8,
                "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            },
            "provider": "mitre",
        },
        "cvssV3_1": {
            "data": {
                "score": 8.8,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            },
            "provider": "mitre",
        },
        "cvssV4_0": {"data": {}, "provider": None},
        "kev": {"data": {}, "provider": None},
        "ssvc": {"data": {}, "provider": None},
        "threat_severity": {"data": None, "provider": None},
    }


@pytest.mark.web_db
def test_process_kb_operator_create_changes(tests_path, tmp_path_factory, web_pg_hook):
    repo = TestRepo("multiple-changes", tests_path, tmp_path_factory)

    # No change
    count_changes = web_pg_hook.get_records("SELECT count(*) FROM opencve_changes;")
    assert count_changes[0][0] == 0

    # FIRST CHANGE
    repo.commit(["2024/CVE-2024-6962.v1.json"], hour=1, minute=00)
    with patch("includes.utils.KB_LOCAL_REPO", repo.repo_path):
        operator = ProcessKbOperator(task_id="parse_test")
        operator.execute(
            {
                "data_interval_start": pendulum.datetime(2024, 1, 1, 1, tz="UTC"),
                "data_interval_end": pendulum.datetime(2024, 1, 1, 2, tz="UTC"),
            }
        )

    # Retrieve the CVE ID
    db_cve_id = web_pg_hook.get_records(
        "SELECT id FROM opencve_cves WHERE cve_id='CVE-2024-6962';"
    )[0][0]

    # We now have 1 change
    count_changes = web_pg_hook.get_records("SELECT count(*) FROM opencve_changes;")
    assert count_changes[0][0] == 1

    # Analyse the 1st change
    db_data = web_pg_hook.get_records(
        "SELECT created_at, updated_at, path, commit, types, cve_id "
        "FROM opencve_changes "
        "WHERE id = '114e2218-49c5-43fe-bcd7-18a1adc17a25';"
    )
    assert db_data[0][0] == datetime.fromisoformat("2024-01-01T00:00:00+00:00")
    assert db_data[0][1] == datetime.fromisoformat("2024-01-01T00:00:00+00:00")
    assert db_data[0][2] == "2024/CVE-2024-6962.v1.json"
    assert db_data[0][3] == "06243efa271b991fc5a9107c6ec7239dc73c08c4"  # predictable
    assert db_data[0][4] == [
        "description",
        "title",
        "weaknesses",
        "references",
        "metrics",
    ]
    assert db_data[0][5] == db_cve_id

    # SECOND CHANGE
    repo.commit(["2024/CVE-2024-6962.v2.json"], hour=2, minute=00)
    with patch("includes.utils.KB_LOCAL_REPO", repo.repo_path):
        operator = ProcessKbOperator(task_id="parse_test")
        operator.execute(
            {
                "data_interval_start": pendulum.datetime(2024, 1, 1, 2, tz="UTC"),
                "data_interval_end": pendulum.datetime(2024, 1, 1, 3, tz="UTC"),
            }
        )

    # We now have 2 changes
    count_changes = web_pg_hook.get_records("SELECT count(*) FROM opencve_changes;")
    assert count_changes[0][0] == 2

    db_data = web_pg_hook.get_records(
        "SELECT created_at, updated_at, path, commit, types, cve_id "
        "FROM opencve_changes "
        "WHERE id = 'd70b3c8b-6f7a-4494-bd01-a2f19f546023';"
    )
    assert db_data[0][0] == datetime.fromisoformat("2024-01-01T01:00:00+00:00")
    assert db_data[0][1] == datetime.fromisoformat("2024-01-01T01:00:00+00:00")
    assert db_data[0][2] == "2024/CVE-2024-6962.v2.json"
    assert db_data[0][3] == "6ab19ef6d05d16d71f0174befc836f7552949dfe"  # predictable
    assert db_data[0][4] == ["title"]
    assert db_data[0][5] == db_cve_id

    # Ensure the first commit hasn't changed
    db_data = web_pg_hook.get_records(
        "SELECT count(*) "
        "FROM opencve_changes "
        "WHERE "
        "(id = '114e2218-49c5-43fe-bcd7-18a1adc17a25' AND commit = '06243efa271b991fc5a9107c6ec7239dc73c08c4') "
        "OR (id = 'd70b3c8b-6f7a-4494-bd01-a2f19f546023' AND commit = '6ab19ef6d05d16d71f0174befc836f7552949dfe');"
    )
    assert db_data[0][0] == 2
