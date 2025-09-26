from unittest.mock import patch
import pathlib
import json

import pendulum
from jinja2 import Environment, FileSystemLoader, select_autoescape

from includes.notifiers import BaseNotifier, EmailNotifier
from utils import TestRepo


def test_prepare_payload(tests_path, tmp_path_factory):
    notification = {
        "project_id": "0439aa01-62b3-465c-ba7b-bd07c961c778",
        "project_name": "orga1-project1",
        "organization_name": "orga1",
        "notification_name": "notification1",
        "notification_type": "webhook",
        "project_subscriptions": ["foo", "foo$PRODUCT$bar"],
        "notification_conf": {
            "types": ["references"],
            "extras": {
                "url": "https://localhost:5000",
                "headers": {"foo": "bar"},
            },
            "metrics": {"cvss31": "4"},
        },
    }

    change_details = {
        "114e2218-49c5-43fe-bcd7-18a1adc17a25": {
            "change_id": "114e2218-49c5-43fe-bcd7-18a1adc17a25",
            "change_types": [
                "description",
                "title",
                "weaknesses",
                "references",
                "metrics",
            ],
            "change_path": "0001/CVE-2024-6962.v1.json",
            "cve_vendors": ["foo", "foo$PRODUCT$bar"],
            "cve_id": "CVE-2024-6962",
            "cve_metrics": {
                "kev": {"data": {}, "provider": None},
                "ssvc": {"data": {}, "provider": None},
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
                "threat_severity": {"data": None, "provider": None},
            },
        }
    }

    repo = TestRepo("changes", tests_path, tmp_path_factory)
    repo.commit(["0001/CVE-2024-6962.v1.json"], hour=1, minute=00)

    notif = BaseNotifier(
        semaphore=None,
        session=None,
        notification=notification,
        changes=["114e2218-49c5-43fe-bcd7-18a1adc17a25"],
        changes_details=change_details,
        period={
            "start": pendulum.datetime(2024, 1, 1, 1, 0, tz="UTC"),
            "end": pendulum.datetime(2024, 1, 1, 2, 0, tz="UTC").subtract(seconds=1),
        },
    )

    with patch("includes.notifiers.KB_LOCAL_REPO", repo.repo_path):
        assert notif.prepare_payload() == {
            "organization": "orga1",
            "project": "orga1-project1",
            "notification": "notification1",
            "matched_subscriptions": {
                "human": [
                    "Bar",
                    "Foo",
                ],
                "raw": ["foo", "foo$PRODUCT$bar"],
            },
            "subscriptions": {
                "human": ["Bar", "Foo"],
                "raw": ["foo", "foo$PRODUCT$bar"],
            },
            "title": "1 change on Bar, Foo",
            "period": {
                "start": "2024-01-01T01:00:00+00:00",
                "end": "2024-01-01T01:59:59+00:00",
            },
            "changes": [
                {
                    "cve": {
                        "cve_id": "CVE-2024-6962",
                        "description": "A vulnerability classified as critical was found in Tenda O3 1.0.0.10. This vulnerability affects the function formQosSet. The manipulation of the argument remark/ipRange/upSpeed/downSpeed/enable leads to stack-based buffer overflow. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-272116. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.",
                        "cvss31": 8.8,
                        "subscriptions": {
                            "human": ["Bar", "Foo"],
                            "raw": ["foo", "foo$PRODUCT$bar"],
                        },
                    },
                    "events": [
                        {
                            "details": {
                                "new": "A vulnerability classified as critical was found in Tenda O3 1.0.0.10. This vulnerability affects the function formQosSet. The manipulation of the argument remark/ipRange/upSpeed/downSpeed/enable leads to stack-based buffer overflow. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-272116. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.",
                                "old": None,
                            },
                            "type": "description",
                        },
                        {
                            "details": {
                                "new": "Tenda O3 formQosSet stack-based overflow",
                                "old": None,
                            },
                            "type": "title",
                        },
                        {
                            "details": {"added": ["CWE-121"], "removed": []},
                            "type": "weaknesses",
                        },
                        {
                            "details": {
                                "added": [
                                    "https://github.com/abcdefg-png/IoT-vulnerable/blob/main/Tenda/O3V2.0/formQosSet.md",
                                    "https://vuldb.com/?ctiid.272116",
                                    "https://vuldb.com/?id.272116",
                                    "https://vuldb.com/?submit.374583",
                                ],
                                "removed": [],
                            },
                            "type": "references",
                        },
                        {
                            "details": {
                                "added": {
                                    "cvssV2_0": {
                                        "score": 9,
                                        "vector": "AV:N/AC:L/Au:S/C:C/I:C/A:C",
                                    },
                                    "cvssV3_0": {
                                        "score": 8.8,
                                        "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                                    },
                                    "cvssV3_1": {
                                        "score": 8.8,
                                        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                                    },
                                },
                                "removed": {},
                                "updated": {},
                            },
                            "type": "metrics",
                        },
                    ],
                }
            ],
        }


def test_generate_email_previews(tests_path, tmp_path_factory):
    """
    This test generates email previews in HTML and TXT formats.
    It's not meant to assert anything, but to provide a visual representation
    of the email notification with different vulnerability severities.
    """
    notification = {
        "project_id": "0439aa01-62b3-465c-ba7b-bd07c961c778",
        "project_name": "orga1-project1",
        "organization_name": "orga1",
        "notification_name": "notification1",
        "notification_type": "email",
        "project_subscriptions": ["foo", "foo$PRODUCT$bar"],
        "notification_conf": {
            "types": ["references", "description"],
            "extras": {
                "email": "foo@bar.com",
            },
            "metrics": {"cvss31": "0"},  # accept all scores
        },
    }

    change_details = {
        # Critical
        "11111111-49c5-43fe-bcd7-18a1adc17a25": {
            "change_id": "11111111-49c5-43fe-bcd7-18a1adc17a25",
            "change_path": "previews/CVE-CRITICAL.json",
            "change_types": ["description"],
            "cve_vendors": ["foo"],
            "cve_id": "CVE-CRITICAL",
            "cve_metrics": {},
        },
        "11111111-49c5-43fe-bcd7-18a1adc17a26": {
            "change_id": "11111111-49c5-43fe-bcd7-18a1adc17a26",
            "change_path": "previews/CVE-CRITICAL-2.json",
            "change_types": ["description"],
            "cve_vendors": ["foo"],
            "cve_id": "CVE-CRITICAL-2",
            "cve_metrics": {},
        },
        # High
        "22222222-49c5-43fe-bcd7-18a1adc17a25": {
            "change_id": "22222222-49c5-43fe-bcd7-18a1adc17a25",
            "change_path": "previews/CVE-HIGH.json",
            "change_types": ["description"],
            "cve_vendors": ["foo"],
            "cve_id": "CVE-HIGH",
            "cve_metrics": {},
        },
        # Medium
        "33333333-49c5-43fe-bcd7-18a1adc17a25": {
            "change_id": "33333333-49c5-43fe-bcd7-18a1adc17a25",
            "change_path": "previews/CVE-MEDIUM.json",
            "change_types": ["description"],
            "cve_vendors": ["foo"],
            "cve_id": "CVE-MEDIUM",
            "cve_metrics": {},
        },
        # Low
        "44444444-49c5-43fe-bcd7-18a1adc17a25": {
            "change_id": "44444444-49c5-43fe-bcd7-18a1adc17a25",
            "change_path": "previews/CVE-LOW.json",
            "change_types": ["description"],
            "cve_vendors": ["foo"],
            "cve_id": "CVE-LOW",
            "cve_metrics": {},
        },
        # None
        "55555555-49c5-43fe-bcd7-18a1adc17a25": {
            "change_id": "55555555-49c5-43fe-bcd7-18a1adc17a25",
            "change_path": "previews/CVE-NONE.json",
            "change_types": ["description"],
            "cve_vendors": ["foo"],
            "cve_id": "CVE-NONE",
            "cve_metrics": {},
        },
    }

    notif = EmailNotifier(
        semaphore=None,
        session=None,
        notification=notification,
        changes=list(change_details.keys()),
        changes_details=change_details,
        period={
            "start": pendulum.datetime(2024, 1, 1, 1, 0, tz="UTC"),
            "end": pendulum.datetime(2024, 1, 1, 2, 0, tz="UTC").subtract(seconds=1),
        },
    )

    kb_path = pathlib.Path(__file__).parent / "data"
    with patch("includes.notifiers.KB_LOCAL_REPO", kb_path):
        context = notif.get_template_context()

    # Render templates
    env = Environment(
        loader=FileSystemLoader(
            pathlib.Path(__file__).parent.parent / "dags/templates"
        ),
        autoescape=select_autoescape(),
    )
    html_template = env.get_template("email_notification.html")
    html_content = html_template.render(context)

    txt_template = env.get_template("email_notification.txt")
    txt_content = txt_template.render(context)

    # Save previews
    previews_dir = pathlib.Path(__file__).parent / "previews"
    previews_dir.mkdir(exist_ok=True)

    html_file = previews_dir / "email_test.html"
    html_file.write_text(html_content)

    txt_file = previews_dir / "email_test.txt"
    txt_file.write_text(txt_content)

    print(f"\nEmail previews generated in: {previews_dir.resolve()}")
