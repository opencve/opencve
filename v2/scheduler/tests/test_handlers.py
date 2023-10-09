import json
import logging

import pytest
from unittest.mock import patch

from includes.handlers import DiffHandler
from includes.handlers.mitre import MitreHandler
from includes.handlers.nvd import NvdHandler
from events.mitre import MitreEvents
from events.nvd import NvdEvents
from constants import SQL_PROCEDURES


logger = logging.getLogger(__name__)


def test_diff_handler_properties(open_file, get_commit, get_diff):
    commit = get_commit("mitre", "c")
    diff = get_diff("mitre", "c", 0)

    handler = DiffHandler(logger, commit, diff)
    assert handler.is_new is False
    assert handler.path == "cves/2023/5xxx/CVE-2023-5301.json"

    # Left is old version of the CVE
    old_version = open_file("mitre/repo/b/cves/2023/5xxx/CVE-2023-5301.json")
    assert handler.left == old_version

    # Right is new version of the CVE
    new_version = open_file("mitre/repo/c/cves/2023/5xxx/CVE-2023-5301.json")
    assert handler.right == new_version


def test_diff_handler_handle(get_commit, get_diff):
    commit = get_commit("mitre", "c")
    diff = get_diff("mitre", "c", 0)
    handler = DiffHandler(logger, commit, diff)

    with pytest.raises(NotImplementedError):
        handler.handle()

    with patch.object(handler, "execute") as execute_mock:
        # If files are not valid we don't execute the handler
        with patch.object(handler, "validate_files") as mock:
            mock.return_value = False
            handler.handle()
            execute_mock.assert_not_called()

        # If files are valid we execute the handler
        with patch.object(handler, "validate_files") as mock:
            mock.return_value = True
            handler.handle()
            execute_mock.assert_called()


@pytest.mark.parametrize(
    "path,result",
    [
        ("", False),
        ("foo", False),
        ("cves/foo/bar", False),
        ("delta.json", False),
        ("deltaLog.json", False),
        ("recent_activities.json", False),
        ("cves/2015/1000xxx/CVE-2015-1000000.json", True),
        ("cves/2023/23xxx/CVE-2023-23002.json", True),
        ("cves/2009/3xxx/CVE-2009-3005.json", True),
    ],
)
def test_mitre_handler_validate_files(get_commit, get_diff, path, result):
    commit = get_commit("mitre", "c")
    diff = get_diff("mitre", "c", 0)

    handler = MitreHandler(logger, commit, diff)
    with patch.object(MitreHandler, "path", path):
        assert handler.validate_files() is result


def test_mitre_handler_get_description(open_file, get_commit, get_diff):
    commit = get_commit("mitre", "c")
    diff_0 = get_diff("mitre", "c", 0)
    diff_1 = get_diff("mitre", "c", 1)

    # c/cves/2023/5xxx/CVE-2023-5301.json
    handler = MitreHandler(logger, commit, diff_0)
    description = handler.get_description()
    assert description == "OpenCVE tests"

    # c/cves/2023/5xxx/CVE-2023-5305.json
    handler = MitreHandler(logger, commit, diff_1)
    description = handler.get_description()
    assert description.startswith(
        "A vulnerability was found in Online Banquet Booking System 1.0"
    )

    # Use the rejectedReasons reason field in case of a REJECTED cve
    cve_data = open_file("mitre/repo/d/cves/2023/2xxx/CVE-2023-2222.json")
    with patch.object(MitreHandler, "right", cve_data):
        description = handler.get_description()
        assert (
            description == "This was deemed not a security vulnerability by upstream."
        )


def test_mitre_handler_get_dates(get_commit, get_diff):
    commit = get_commit("mitre", "c")
    diff_0 = get_diff("mitre", "c", 0)
    diff_1 = get_diff("mitre", "c", 1)

    # c/cves/2023/5xxx/CVE-2023-5301.json
    handler = MitreHandler(logger, commit, diff_0)
    created, updated = handler.get_dates()
    assert created == "2023-09-30T10:31:04.312000+00:00"
    assert updated == "2023-09-30T10:31:04.312000+00:00"

    # c/cves/2023/5xxx/CVE-2023-5305.json
    handler = MitreHandler(logger, commit, diff_1)
    created, updated = handler.get_dates()
    assert created == "2023-09-30T14:31:04.346000+00:00"
    assert updated == "2023-09-30T14:31:04.346000+00:00"

    # Use the datePublished and dateUpdated
    cve_data = {
        "cveMetadata": {
            "dateReserved": "2023-01-01T00:00:00.000Z",
            "datePublished": "2023-01-02T00:00:00.000Z",
            "dateUpdated": "2023-01-03T00:00:00.000Z",
        }
    }
    with patch.object(MitreHandler, "right", cve_data):
        created, updated = handler.get_dates()
        assert created == "2023-01-02T00:00:00+00:00"
        assert updated == "2023-01-03T00:00:00+00:00"

    # Rejected CVEs doesn't have published date
    cve_data = {
        "cveMetadata": {
            "dateReserved": "2023-01-01T00:00:00.000Z",
            "dateUpdated": "2023-01-03T00:00:00.000Z",
        }
    }
    with patch.object(MitreHandler, "right", cve_data):
        created, updated = handler.get_dates()
        assert created == "2023-01-01T00:00:00+00:00"
        assert updated == "2023-01-03T00:00:00+00:00"

    # Recent CVEs doesn't have updated date
    cve_data = {
        "cveMetadata": {
            "dateReserved": "2023-01-01T00:00:00.000Z",
            "datePublished": "2023-01-02T00:00:00.000Z",
        }
    }
    with patch.object(MitreHandler, "right", cve_data):
        created, updated = handler.get_dates()
        assert created == "2023-01-02T00:00:00+00:00"
        assert updated == "2023-01-02T00:00:00+00:00"


@patch("includes.handlers.run_sql")
def test_mitre_handler_create_change_new(run_sql_mock, get_commit, get_diff):
    commit = get_commit("mitre", "c")
    diff = get_diff("mitre", "c", 1)

    handler = MitreHandler(logger, commit, diff)
    with patch.object(handler, "execute"):
        handler.handle()

    # Create a change between commits `b` and `c`
    handler.create_change("CVE-2023-5305", MitreEvents)
    _, kwargs = run_sql_mock.call_args
    assert kwargs["query"] == SQL_PROCEDURES.get("events")

    # The CVE-2023-5305 cve appeared in commit `c`
    parameters = kwargs["parameters"]
    assert parameters["cve"] == "CVE-2023-5305"
    assert parameters["created"] == "2023-01-01T02:10:00+00:00"
    assert parameters["updated"] == "2023-01-01T02:10:00+00:00"
    assert parameters["path"] == "cves/2023/5xxx/CVE-2023-5305.json"
    assert len(parameters["events"].adapted) == 1
    assert parameters["events"].adapted[0]["type"] == "mitre_new"


@patch("includes.handlers.run_sql")
def test_mitre_handler_create_change_update(run_sql_mock, get_commit, get_diff):
    commit = get_commit("mitre", "c")
    diff = get_diff("mitre", "c", 0)

    handler = MitreHandler(logger, commit, diff)
    with patch.object(handler, "execute"):
        handler.handle()

    # Create a change between commits `b` and `c`
    handler.create_change("CVE-2023-5301", MitreEvents)
    _, kwargs = run_sql_mock.call_args
    assert kwargs["query"] == SQL_PROCEDURES.get("events")

    # The summary of CVE-2023-5301 was changed in commit `c`
    parameters = kwargs["parameters"]
    assert parameters["cve"] == "CVE-2023-5301"
    assert parameters["created"] == "2023-01-01T02:10:00+00:00"
    assert parameters["updated"] == "2023-01-01T02:10:00+00:00"
    assert parameters["path"] == "cves/2023/5xxx/CVE-2023-5301.json"
    assert len(parameters["events"].adapted) == 1
    assert parameters["events"].adapted[0]["type"] == "mitre_summary"


@patch("includes.handlers.run_sql")
def test_nvd_handler_create_change_new(run_sql_mock, get_commit, get_diff):
    commit = get_commit("nvd", "c")
    diff = get_diff("nvd", "c", 1)

    handler = NvdHandler(logger, commit, diff)
    with patch.object(handler, "execute"):
        handler.handle()

    # Create a change between commits `b` and `c`
    handler.create_change("CVE-2023-5305", NvdEvents)
    _, kwargs = run_sql_mock.call_args
    assert kwargs["query"] == SQL_PROCEDURES.get("events")

    # The CVE-2023-5305 cve appeared in commit `c`
    parameters = kwargs["parameters"]
    assert parameters["cve"] == "CVE-2023-5305"
    assert parameters["created"] == "2023-01-01T02:10:00+00:00"
    assert parameters["updated"] == "2023-01-01T02:10:00+00:00"
    assert parameters["path"] == "2023/CVE-2023-5305.json"
    assert len(parameters["events"].adapted) == 1
    assert parameters["events"].adapted[0]["type"] == "nvd_new"


@patch("includes.handlers.run_sql")
def test_nvd_handler_create_change_update(run_sql_mock, get_commit, get_diff):
    commit = get_commit("nvd", "c")
    diff = get_diff("nvd", "c", 0)

    handler = NvdHandler(logger, commit, diff)
    with patch.object(handler, "execute"):
        handler.handle()

    # Create a change between commits `b` and `c`
    handler.create_change("CVE-2023-5301", NvdEvents)
    _, kwargs = run_sql_mock.call_args
    assert kwargs["query"] == SQL_PROCEDURES.get("events")

    # The summary of CVE-2023-5301 was changed in commit `c`
    parameters = kwargs["parameters"]
    assert parameters["cve"] == "CVE-2023-5301"
    assert parameters["created"] == "2023-01-01T02:10:00+00:00"
    assert parameters["updated"] == "2023-01-01T02:10:00+00:00"
    assert parameters["path"] == "2023/CVE-2023-5301.json"
    assert len(parameters["events"].adapted) == 1
    assert parameters["events"].adapted[0]["type"] == "nvd_summary"
