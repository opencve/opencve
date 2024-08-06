import logging
from unittest.mock import patch

import pendulum

from utils import TestRepo
from includes.utils import (
    divide_list,
    group_changes_by_vendor,
    format_change_details,
    merge_project_subscriptions,
    list_changes_by_project,
    group_notifications_by_project,
    get_dates_from_context,
    list_commits,
)


logger = logging.getLogger(__name__)


def test_divide_list():
    assert divide_list(["a", "b", "c", "d"], 5) == [["a"], ["b"], ["c"], ["d"]]
    assert divide_list(["a", "b", "c", "d"], 4) == [["a"], ["b"], ["c"], ["d"]]
    assert divide_list(["a", "b", "c", "d"], 3) == [["a", "b"], ["c"], ["d"]]
    assert divide_list(["a", "b", "c", "d"], 2) == [["a", "b"], ["c", "d"]]
    assert divide_list(["a", "b", "c", "d"], 1) == [["a", "b", "c", "d"]]


def test_group_changes_by_vendor():
    records = [
        ("change1", [], "", ["vendor1", "product1"], "", {}),
        ("change2", [], "", ["vendor2", "product2"], "", {}),
        ("change3", [], "", ["vendor3", "product3"], "", {}),
        ("change4", [], "", ["vendor1", "product2"], "", {}),
    ]

    assert group_changes_by_vendor(records) == {
        "vendor1": ["change1", "change4"],
        "vendor2": ["change2"],
        "vendor3": ["change3"],
        "product1": ["change1"],
        "product2": ["change2", "change4"],
        "product3": ["change3"],
    }


def test_format_change_details():
    records = [
        (
            "change1",
            ["type1"],
            "2024/CVE-2024-0001.json",
            ["vendor1"],
            "CVE-2024-0001",
            {"cvssV3_1": {}},
        ),
        (
            "change2",
            ["type2"],
            "2024/CVE-2024-0002.json",
            ["vendor2"],
            "CVE-2024-0002",
            {"cvssV4_0": {}},
        ),
    ]
    assert format_change_details(records) == {
        "change1": {
            "change_id": "change1",
            "change_types": ["type1"],
            "change_path": "2024/CVE-2024-0001.json",
            "cve_vendors": ["vendor1"],
            "cve_id": "CVE-2024-0001",
            "cve_metrics": {"cvssV3_1": {}},
        },
        "change2": {
            "change_id": "change2",
            "change_types": ["type2"],
            "change_path": "2024/CVE-2024-0002.json",
            "cve_vendors": ["vendor2"],
            "cve_id": "CVE-2024-0002",
            "cve_metrics": {"cvssV4_0": {}},
        },
    }


def test_merge_project_subscriptions():
    records = [
        ("project1", {"vendors": [], "products": ["product1"]}),
        ("project2", {"vendors": ["vendor1"], "products": []}),
        ("project3", {"vendors": ["vendor1"], "products": ["product1"]}),
        (
            "project4",
            {"vendors": ["vendor1", "vendor2"], "products": ["product1", "product2"]},
        ),
    ]
    assert merge_project_subscriptions(records) == {
        "project1": ["product1"],
        "project2": ["vendor1"],
        "project3": ["vendor1", "product1"],
        "project4": ["vendor1", "vendor2", "product1", "product2"],
    }


def test_list_changes_by_project():
    changes = {
        "vendor1": ["change1"],
        "vendor2": ["change1", "change2"],
        "vendor3": ["change3"],
    }
    subscriptions = {
        "project1": [],
        "project2": ["vendor1"],
        "project3": ["vendor2"],
        "project4": ["vendor1", "vendor2"],
        "project5": ["vendor1", "vendor2", "vendor3"],
    }
    assert sorted(list_changes_by_project(changes, subscriptions)) == sorted(
        {
            "project2": ["change1"],
            "project3": ["change1", "change2"],
            "project4": ["change1", "change2"],
            "project5": ["change1", "change2", "change3"],
        }
    )


def test_get_project_notifications():
    records = [
        (
            "project-id-1",
            "project-name-1",
            "organization-1",
            "notification-1",
            "webhook",
            {
                "types": ["created", "weaknesses", "cpes"],
                "extras": {"url": "https://localhost:5000", "headers": {"foo": "bar"}},
                "metrics": {"cvss31": "4"},
            },
        ),
        (
            "project-id-1",
            "project-name-1",
            "organization-1",
            "notification-2",
            "email",
            {
                "types": ["references"],
                "extras": {},
                "metrics": {"cvss31": "8"},
            },
        ),
        (
            "project-id-2",
            "project-name-2",
            "organization-2",
            "notification-3",
            "email",
            {
                "types": ["cpes"],
                "extras": {},
                "metrics": {"cvss31": "0"},
            },
        ),
    ]
    assert group_notifications_by_project(records) == {
        "project-id-1": [
            {
                "project_id": "project-id-1",
                "project_name": "project-name-1",
                "organization_name": "organization-1",
                "notification_name": "notification-1",
                "notification_type": "webhook",
                "notification_conf": {
                    "types": ["created", "weaknesses", "cpes"],
                    "extras": {
                        "url": "https://localhost:5000",
                        "headers": {"foo": "bar"},
                    },
                    "metrics": {"cvss31": "4"},
                },
            },
            {
                "project_id": "project-id-1",
                "project_name": "project-name-1",
                "organization_name": "organization-1",
                "notification_name": "notification-2",
                "notification_type": "email",
                "notification_conf": {
                    "types": ["references"],
                    "extras": {},
                    "metrics": {"cvss31": "8"},
                },
            },
        ],
        "project-id-2": [
            {
                "project_id": "project-id-2",
                "project_name": "project-name-2",
                "organization_name": "organization-2",
                "notification_name": "notification-3",
                "notification_type": "email",
                "notification_conf": {
                    "types": ["cpes"],
                    "extras": {},
                    "metrics": {"cvss31": "0"},
                },
            }
        ],
    }


def test_get_dates_from_context():
    context = {
        "data_interval_start": pendulum.parse("2024-01-01T10:00:00"),
        "data_interval_end": pendulum.parse("2024-01-01T11:00:00"),
    }
    assert get_dates_from_context(context) == (
        pendulum.parse("2024-01-01T10:00:00"),
        pendulum.parse("2024-01-01T10:59:59"),
    )


def test_list_commits(tests_path, tmp_path_factory):
    repo = TestRepo("example", tests_path, tmp_path_factory)
    commit_a = repo.commit(["a/"], hour=1, minute=00)
    commit_b = repo.commit(["b/"], hour=2, minute=00)
    commit_c = repo.commit(["c/"], hour=2, minute=30)

    with patch("includes.utils.KB_LOCAL_REPO", repo.repo_path):
        # No commit between 12:00 and 12:59:59
        assert (
            list_commits(
                logger,
                pendulum.datetime(2024, 1, 1, 12, tz="UTC"),
                pendulum.datetime(2024, 1, 1, 13, tz="UTC"),
            )
            == []
        )

        # One commit between 01:00 and 01:59:59
        assert list_commits(
            logger,
            pendulum.datetime(2024, 1, 1, 1, tz="UTC"),
            pendulum.datetime(2024, 1, 1, 2, tz="UTC"),
        ) == [commit_a]

        # Two commits between 02:00 and 02:59:59
        assert list_commits(
            logger,
            pendulum.datetime(2024, 1, 1, 2, tz="UTC"),
            pendulum.datetime(2024, 1, 1, 3, tz="UTC"),
        ) == [commit_b, commit_c]

        # Three commits between 10:00 and 02:59:59
        assert list_commits(
            logger,
            pendulum.datetime(2024, 1, 1, 1, tz="UTC"),
            pendulum.datetime(2024, 1, 1, 3, tz="UTC"),
        ) == [commit_a, commit_b, commit_c]
