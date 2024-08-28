import json
from pathlib import Path
from unittest.mock import patch

import git
import pendulum

from includes.handler import DiffHandler
from utils import TestRepo


def test_diff_handler_properties(tests_path, tmp_path_factory, open_file):
    repo = TestRepo("multiple-changes", tests_path, tmp_path_factory)
    commit = repo.commit(["2024/CVE-2024-6962.v1.json"], hour=1, minute=00)
    diff = commit.parents[0].diff(commit)[0]

    handler = DiffHandler(diff, commit.hexsha)
    assert handler.path == "2024/CVE-2024-6962.v1.json"
    assert handler.filename == "CVE-2024-6962.v1.json"

    with patch("includes.handler.KB_LOCAL_REPO", Path("/path/")):
        assert handler.full_path == Path("/path/2024/CVE-2024-6962.v1.json")

    cve_data = open_file("multiple-changes/2024/CVE-2024-6962.v1.json")
    assert handler.data == cve_data


def test_diff_handler_is_new_file(tests_path, tmp_path_factory):
    test_repo = TestRepo("multiple-changes", tests_path, tmp_path_factory)
    commit = test_repo.commit(["2024/CVE-2024-6962.v1.json"], hour=1, minute=00)
    diff = commit.parents[0].diff(commit)[0]

    # The first commit contains the new CVE
    handler = DiffHandler(diff, commit.hexsha)
    assert handler.is_new_file()

    # The second commit is an update of the existing CVE
    with open(test_repo.repo_path / "2024/CVE-2024-6962.v1.json", "w") as f:
        json.dump({"foo": "bar"}, f)
    date = pendulum.datetime(2024, 1, 1, 2, 0, tz="UTC")
    test_repo.repo.git.add(A=True)
    commit = test_repo.repo.index.commit(
        f"Updates for 2:0",
        author=git.Actor("opencve", "opencve@example.com"),
        committer=git.Actor("opencve", "opencve@example.com"),
        commit_date=date,
        author_date=date,
    )

    diff = commit.parents[0].diff(commit)[0]
    handler = DiffHandler(diff, commit.hexsha)
    assert not handler.is_new_file()
    assert handler.data == {"foo": "bar"}


def test_diff_handler_format_cve(tests_path, tmp_path_factory):
    repo = TestRepo("multiple-changes", tests_path, tmp_path_factory)
    commit = repo.commit(["2024/CVE-2024-6962.v1.json"], hour=1, minute=00)
    diff = commit.parents[0].diff(commit)[0]

    handler = DiffHandler(diff, commit.hexsha)
    cve_data = handler.format_cve()

    assert cve_data["cve"] == "CVE-2024-6962"
    assert cve_data["created"] == "2024-01-01T00:00:00+00:00"
    assert cve_data["updated"] == "2024-01-01T00:00:00+00:00"
    assert cve_data["title"] == "Tenda O3 formQosSet stack-based overflow"
    assert (
        cve_data["description"]
        == "A vulnerability classified as critical was found in Tenda O3 1.0.0.10. This vulnerability affects the function formQosSet. The manipulation of the argument remark/ipRange/upSpeed/downSpeed/enable leads to stack-based buffer overflow. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-272116. NOTE: The vendor was contacted early about this disclosure but did not respond in any way."
    )
    assert cve_data["vendors"].adapted == ["foo", "foo$PRODUCT$bar"]
    assert cve_data["weaknesses"].adapted == ["CWE-121"]
    assert cve_data["metrics"].adapted == {
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
    assert cve_data["changes"].adapted == [
        {
            "change": "114e2218-49c5-43fe-bcd7-18a1adc17a25",
            "created": "2024-01-01T00:00:00+00:00",
            "updated": "2024-01-01T00:00:00+00:00",
            "file_path": "2024/CVE-2024-6962.v1.json",
            "commit_hash": "06243efa271b991fc5a9107c6ec7239dc73c08c4",  # predictable
            "event_types": [
                "description",
                "title",
                "weaknesses",
                "references",
                "metrics",
            ],
        }
    ]


def test_diff_handler_singletons(tests_path, tmp_path_factory):
    repo = TestRepo("multiple-changes", tests_path, tmp_path_factory)
    commit = repo.commit(["2024/CVE-2024-6962.v1.json"], hour=1, minute=00)
    diff = commit.parents[0].diff(commit)[0]
    handler = DiffHandler(diff, commit.hexsha)

    path1 = handler.path
    path2 = handler.path
    assert id(path1) == id(path2)

    data1 = handler.data
    data2 = handler.data
    assert id(data1) == id(data2)
