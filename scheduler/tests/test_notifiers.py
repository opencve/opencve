from unittest.mock import patch, AsyncMock, MagicMock
import pathlib
import json

import pendulum
import pytest
import aiohttp
import asyncio
from jinja2 import Environment, FileSystemLoader, select_autoescape

from includes.notifiers import (
    BaseNotifier,
    EmailNotifier,
    WebhookNotifier,
    SlackNotifier,
)
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


def test_email_notifier_template_context_created_by_and_unsubscribe_url(
    tests_path, tmp_path_factory
):
    """EmailNotifier get_template_context includes created_by_email and unsubscribe_url from extras."""
    notification = {
        "project_name": "test-project",
        "organization_name": "test-org",
        "notification_name": "test-notif",
        "notification_type": "email",
        "project_subscriptions": ["foo"],
        "notification_conf": {
            "types": ["created"],
            "extras": {
                "email": "target@example.com",
                "created_by_email": "creator@example.com",
                "unsubscribe_token": "my-unsubscribe-token",
            },
            "metrics": {"cvss31": "0"},
        },
    }

    change_details = {
        "114e2218-49c5-43fe-bcd7-18a1adc17a25": {
            "change_id": "114e2218-49c5-43fe-bcd7-18a1adc17a25",
            "change_path": "0001/CVE-2024-6962.v1.json",
            "change_types": ["created"],
            "cve_vendors": ["foo"],
            "cve_id": "CVE-2024-6962",
            "cve_metrics": {
                "cvssV3_1": {
                    "data": {"score": 8.8},
                    "provider": "mitre",
                }
            },
        }
    }

    repo = TestRepo("changes", tests_path, tmp_path_factory)
    repo.commit(["0001/CVE-2024-6962.v1.json"], hour=1, minute=00)

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

    with patch("includes.notifiers.KB_LOCAL_REPO", repo.repo_path), patch(
        "includes.notifiers.conf"
    ) as mock_conf:
        mock_conf.get.return_value = "https://opencve.example.com"
        context = notif.get_template_context()

    assert context["created_by_email"] == "creator@example.com"
    assert context["unsubscribe_url"] == (
        "https://opencve.example.com/notifications/unsubscribe/my-unsubscribe-token"
    )


# Tests for BaseNotifier utility methods


def test_humanize_subscription():
    assert BaseNotifier.humanize_subscription("foo") == "Foo"
    assert BaseNotifier.humanize_subscription("foo_bar") == "Foo Bar"
    assert BaseNotifier.humanize_subscription("foo$PRODUCT$bar") == "Bar"
    assert BaseNotifier.humanize_subscription("FOO_BAR") == "Foo Bar"
    assert BaseNotifier.humanize_subscription("foo_bar_baz") == "Foo Bar Baz"


def test_humanize_subscriptions():
    subscriptions = ["foo", "bar_baz", "test$PRODUCT$value"]
    result = BaseNotifier.humanize_subscriptions(subscriptions)
    assert result == ["Foo", "Bar Baz", "Value"]


def test_get_title():
    payload1 = {
        "changes": [{"cve": {"cve_id": "CVE-2024-0001"}}],
        "matched_subscriptions": {"human": ["Foo"]},
    }
    assert BaseNotifier.get_title(payload1) == "1 change on Foo"

    payload2 = {
        "changes": [
            {"cve": {"cve_id": "CVE-2024-0001"}},
            {"cve": {"cve_id": "CVE-2024-0002"}},
        ],
        "matched_subscriptions": {"human": ["Bar", "Foo"]},
    }
    assert BaseNotifier.get_title(payload2) == "2 changes on Bar, Foo"


def test_get_severity_str():
    assert BaseNotifier.get_severity_str(None) == "none"
    assert BaseNotifier.get_severity_str(0.0) == "none"  # 0.0 is falsy, treated as none
    assert BaseNotifier.get_severity_str(0.1) == "low"
    assert BaseNotifier.get_severity_str(3.9) == "low"
    assert BaseNotifier.get_severity_str(4.0) == "medium"
    assert BaseNotifier.get_severity_str(6.9) == "medium"
    assert BaseNotifier.get_severity_str(7.0) == "high"
    assert BaseNotifier.get_severity_str(8.9) == "high"
    assert BaseNotifier.get_severity_str(9.0) == "critical"
    assert BaseNotifier.get_severity_str(10.0) == "critical"
    assert BaseNotifier.get_severity_str(11.0) == "none"  # Invalid score


# Tests for WebhookNotifier


def test_webhook_notifier_init():
    notification = {
        "project_name": "test-project",
        "organization_name": "test-org",
        "notification_name": "test-notif",
        "notification_conf": {
            "extras": {
                "url": "https://example.com/webhook",
                "headers": {"Authorization": "Bearer token"},
            }
        },
    }

    notifier = WebhookNotifier(
        semaphore=None,
        session=None,
        notification=notification,
        changes=[],
        changes_details={},
        period={"start": "2024-01-01", "end": "2024-01-02"},
    )

    assert notifier.url == "https://example.com/webhook"
    assert notifier.headers == {"Authorization": "Bearer token"}


@pytest.mark.asyncio
async def test_webhook_notifier_send_success(tests_path, tmp_path_factory):
    notification = {
        "project_name": "test-project",
        "organization_name": "test-org",
        "notification_name": "test-notif",
        "project_subscriptions": ["foo"],
        "notification_conf": {
            "extras": {
                "url": "https://example.com/webhook",
                "headers": {"Authorization": "Bearer token"},
            }
        },
    }

    change_details = {
        "114e2218-49c5-43fe-bcd7-18a1adc17a25": {
            "change_id": "114e2218-49c5-43fe-bcd7-18a1adc17a25",
            "change_path": "0001/CVE-2024-6962.v1.json",
            "cve_vendors": ["foo"],
            "cve_id": "CVE-2024-6962",
            "cve_metrics": {},
        }
    }

    repo = TestRepo("changes", tests_path, tmp_path_factory)
    repo.commit(["0001/CVE-2024-6962.v1.json"], hour=1, minute=00)

    semaphore = asyncio.Semaphore(10)
    session = AsyncMock()
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.json = AsyncMock(return_value={"status": "ok"})
    session.post.return_value.__aenter__.return_value = mock_response

    notifier = WebhookNotifier(
        semaphore=semaphore,
        session=session,
        notification=notification,
        changes=["114e2218-49c5-43fe-bcd7-18a1adc17a25"],
        changes_details=change_details,
        period={
            "start": pendulum.datetime(2024, 1, 1, 1, 0, tz="UTC"),
            "end": pendulum.datetime(2024, 1, 1, 2, 0, tz="UTC").subtract(seconds=1),
        },
    )

    with patch("includes.notifiers.KB_LOCAL_REPO", repo.repo_path):
        result = await notifier.execute()

    assert result == {}
    session.post.assert_called_once()
    call_kwargs = session.post.call_args
    assert call_kwargs[0][0] == "https://example.com/webhook"
    assert "json" in call_kwargs[1]
    assert call_kwargs[1]["headers"] == {"Authorization": "Bearer token"}


@pytest.mark.asyncio
async def test_webhook_notifier_send_connection_error(tests_path, tmp_path_factory):
    notification = {
        "project_name": "test-project",
        "organization_name": "test-org",
        "notification_name": "test-notif",
        "project_subscriptions": ["foo"],
        "notification_conf": {
            "extras": {
                "url": "https://example.com/webhook",
                "headers": {},
            }
        },
    }

    change_details = {
        "114e2218-49c5-43fe-bcd7-18a1adc17a25": {
            "change_id": "114e2218-49c5-43fe-bcd7-18a1adc17a25",
            "change_path": "0001/CVE-2024-6962.v1.json",
            "cve_vendors": ["foo"],
            "cve_id": "CVE-2024-6962",
            "cve_metrics": {},
        }
    }

    repo = TestRepo("changes", tests_path, tmp_path_factory)
    repo.commit(["0001/CVE-2024-6962.v1.json"], hour=1, minute=00)

    semaphore = asyncio.Semaphore(10)
    session = AsyncMock()

    # Create ClientConnectorError
    connection_key = MagicMock()
    os_error = OSError("Connection refused")
    os_error.errno = 61  # Connection refused error code
    session.post.side_effect = aiohttp.ClientConnectorError(
        connection_key, os_error=os_error
    )

    notifier = WebhookNotifier(
        semaphore=semaphore,
        session=session,
        notification=notification,
        changes=["114e2218-49c5-43fe-bcd7-18a1adc17a25"],
        changes_details=change_details,
        period={
            "start": pendulum.datetime(2024, 1, 1, 1, 0, tz="UTC"),
            "end": pendulum.datetime(2024, 1, 1, 2, 0, tz="UTC").subtract(seconds=1),
        },
    )

    with patch("includes.notifiers.KB_LOCAL_REPO", repo.repo_path):
        result = await notifier.execute()

    assert result == {}


@pytest.mark.asyncio
async def test_webhook_notifier_send_timeout_error(tests_path, tmp_path_factory):
    notification = {
        "project_name": "test-project",
        "organization_name": "test-org",
        "notification_name": "test-notif",
        "project_subscriptions": ["foo"],
        "notification_conf": {
            "extras": {
                "url": "https://example.com/webhook",
                "headers": {},
            }
        },
    }

    change_details = {
        "114e2218-49c5-43fe-bcd7-18a1adc17a25": {
            "change_id": "114e2218-49c5-43fe-bcd7-18a1adc17a25",
            "change_path": "0001/CVE-2024-6962.v1.json",
            "cve_vendors": ["foo"],
            "cve_id": "CVE-2024-6962",
            "cve_metrics": {},
        }
    }

    repo = TestRepo("changes", tests_path, tmp_path_factory)
    repo.commit(["0001/CVE-2024-6962.v1.json"], hour=1, minute=00)

    semaphore = asyncio.Semaphore(10)
    session = AsyncMock()
    session.post.side_effect = asyncio.TimeoutError()

    notifier = WebhookNotifier(
        semaphore=semaphore,
        session=session,
        notification=notification,
        changes=["114e2218-49c5-43fe-bcd7-18a1adc17a25"],
        changes_details=change_details,
        period={
            "start": pendulum.datetime(2024, 1, 1, 1, 0, tz="UTC"),
            "end": pendulum.datetime(2024, 1, 1, 2, 0, tz="UTC").subtract(seconds=1),
        },
    )

    with patch("includes.notifiers.KB_LOCAL_REPO", repo.repo_path):
        result = await notifier.execute()

    assert result == {}


# Tests for SlackNotifier


def test_slack_notifier_init():
    notification = {
        "project_name": "test-project",
        "organization_name": "test-org",
        "notification_name": "test-notif",
        "notification_conf": {
            "extras": {
                "webhook_url": "https://hooks.slack.com/webhook",
            }
        },
    }

    notifier = SlackNotifier(
        semaphore=None,
        session=None,
        notification=notification,
        changes=[],
        changes_details={},
        period={"start": "2024-01-01", "end": "2024-01-02"},
    )

    assert notifier.webhook_url == "https://hooks.slack.com/webhook"


def test_slack_notifier_format_slack_blocks(tests_path, tmp_path_factory):
    notification = {
        "project_name": "test-project",
        "organization_name": "test-org",
        "notification_name": "test-notif",
        "project_subscriptions": ["foo"],
        "notification_conf": {
            "extras": {
                "webhook_url": "https://hooks.slack.com/webhook",
            }
        },
    }

    change_details = {
        "114e2218-49c5-43fe-bcd7-18a1adc17a25": {
            "change_id": "114e2218-49c5-43fe-bcd7-18a1adc17a25",
            "change_path": "0001/CVE-2024-6962.v1.json",
            "cve_vendors": ["foo"],
            "cve_id": "CVE-2024-6962",
            "cve_metrics": {},
        }
    }

    repo = TestRepo("changes", tests_path, tmp_path_factory)
    repo.commit(["0001/CVE-2024-6962.v1.json"], hour=1, minute=00)

    notifier = SlackNotifier(
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
        messages = notifier.format_slack_blocks()

    assert isinstance(messages, list)
    assert len(messages) > 0
    assert "blocks" in messages[0]
    assert len(messages[0]["blocks"]) > 0

    # Check first block contains title
    first_block = messages[0]["blocks"][0]
    assert first_block["type"] == "section"
    assert "test-org" in first_block["text"]["text"]
    assert "test-project" in first_block["text"]["text"]


def test_slack_notifier_format_slack_blocks_multiple_severities(
    tests_path, tmp_path_factory
):
    """Test that Slack blocks properly group CVEs by severity"""
    notification = {
        "project_name": "test-project",
        "organization_name": "test-org",
        "notification_name": "test-notif",
        "project_subscriptions": ["foo"],
        "notification_conf": {
            "extras": {
                "webhook_url": "https://hooks.slack.com/webhook",
            }
        },
    }

    # Create multiple changes with different severities
    change_details = {
        "critical": {
            "change_id": "critical",
            "change_path": "previews/CVE-CRITICAL.json",
            "cve_vendors": ["foo"],
            "cve_id": "CVE-CRITICAL",
            "cve_metrics": {},
        },
        "high": {
            "change_id": "high",
            "change_path": "previews/CVE-HIGH.json",
            "cve_vendors": ["foo"],
            "cve_id": "CVE-HIGH",
            "cve_metrics": {},
        },
        "low": {
            "change_id": "low",
            "change_path": "previews/CVE-LOW.json",
            "cve_vendors": ["foo"],
            "cve_id": "CVE-LOW",
            "cve_metrics": {},
        },
    }

    kb_path = pathlib.Path(__file__).parent / "data"

    notifier = SlackNotifier(
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

    with patch("includes.notifiers.KB_LOCAL_REPO", kb_path):
        messages = notifier.format_slack_blocks()

    assert isinstance(messages, list)
    assert len(messages) > 0

    # Check that blocks contain severity sections
    blocks_text = " ".join(
        block.get("text", {}).get("text", "")
        for message in messages
        for block in message.get("blocks", [])
        if block.get("type") == "section"
    )

    # Should contain severity indicators
    assert "CRITICAL" in blocks_text or "HIGH" in blocks_text or "LOW" in blocks_text


@pytest.mark.asyncio
async def test_slack_notifier_send_success(tests_path, tmp_path_factory):
    notification = {
        "project_name": "test-project",
        "organization_name": "test-org",
        "notification_name": "test-notif",
        "project_subscriptions": ["foo"],
        "notification_conf": {
            "extras": {
                "webhook_url": "https://hooks.slack.com/webhook",
            }
        },
    }

    change_details = {
        "114e2218-49c5-43fe-bcd7-18a1adc17a25": {
            "change_id": "114e2218-49c5-43fe-bcd7-18a1adc17a25",
            "change_path": "0001/CVE-2024-6962.v1.json",
            "cve_vendors": ["foo"],
            "cve_id": "CVE-2024-6962",
            "cve_metrics": {},
        }
    }

    repo = TestRepo("changes", tests_path, tmp_path_factory)
    repo.commit(["0001/CVE-2024-6962.v1.json"], hour=1, minute=00)

    semaphore = asyncio.Semaphore(10)
    session = AsyncMock()
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.text = AsyncMock(return_value="ok")
    session.post.return_value.__aenter__.return_value = mock_response

    notifier = SlackNotifier(
        semaphore=semaphore,
        session=session,
        notification=notification,
        changes=["114e2218-49c5-43fe-bcd7-18a1adc17a25"],
        changes_details=change_details,
        period={
            "start": pendulum.datetime(2024, 1, 1, 1, 0, tz="UTC"),
            "end": pendulum.datetime(2024, 1, 1, 2, 0, tz="UTC").subtract(seconds=1),
        },
    )

    with patch("includes.notifiers.KB_LOCAL_REPO", repo.repo_path):
        await notifier.execute()

    session.post.assert_called()
    call_kwargs = session.post.call_args
    assert call_kwargs[0][0] == "https://hooks.slack.com/webhook"
    assert call_kwargs[1]["headers"] == {"Content-Type": "application/json"}
    assert "json" in call_kwargs[1]


@pytest.mark.asyncio
async def test_slack_notifier_send_error(tests_path, tmp_path_factory):
    notification = {
        "project_name": "test-project",
        "organization_name": "test-org",
        "notification_name": "test-notif",
        "project_subscriptions": ["foo"],
        "notification_conf": {
            "extras": {
                "webhook_url": "https://hooks.slack.com/webhook",
            }
        },
    }

    change_details = {
        "114e2218-49c5-43fe-bcd7-18a1adc17a25": {
            "change_id": "114e2218-49c5-43fe-bcd7-18a1adc17a25",
            "change_path": "0001/CVE-2024-6962.v1.json",
            "cve_vendors": ["foo"],
            "cve_id": "CVE-2024-6962",
            "cve_metrics": {},
        }
    }

    repo = TestRepo("changes", tests_path, tmp_path_factory)
    repo.commit(["0001/CVE-2024-6962.v1.json"], hour=1, minute=00)

    semaphore = asyncio.Semaphore(10)
    session = AsyncMock()
    mock_response = AsyncMock()
    mock_response.status = 400
    mock_response.text = AsyncMock(return_value="invalid_payload")
    session.post.return_value.__aenter__.return_value = mock_response

    notifier = SlackNotifier(
        semaphore=semaphore,
        session=session,
        notification=notification,
        changes=["114e2218-49c5-43fe-bcd7-18a1adc17a25"],
        changes_details=change_details,
        period={
            "start": pendulum.datetime(2024, 1, 1, 1, 0, tz="UTC"),
            "end": pendulum.datetime(2024, 1, 1, 2, 0, tz="UTC").subtract(seconds=1),
        },
    )

    with patch("includes.notifiers.KB_LOCAL_REPO", repo.repo_path):
        await notifier.execute()

    # Should still complete without raising
    session.post.assert_called()


@pytest.mark.asyncio
async def test_slack_notifier_send_exception(tests_path, tmp_path_factory):
    notification = {
        "project_name": "test-project",
        "organization_name": "test-org",
        "notification_name": "test-notif",
        "project_subscriptions": ["foo"],
        "notification_conf": {
            "extras": {
                "webhook_url": "https://hooks.slack.com/webhook",
            }
        },
    }

    change_details = {
        "114e2218-49c5-43fe-bcd7-18a1adc17a25": {
            "change_id": "114e2218-49c5-43fe-bcd7-18a1adc17a25",
            "change_path": "0001/CVE-2024-6962.v1.json",
            "cve_vendors": ["foo"],
            "cve_id": "CVE-2024-6962",
            "cve_metrics": {},
        }
    }

    repo = TestRepo("changes", tests_path, tmp_path_factory)
    repo.commit(["0001/CVE-2024-6962.v1.json"], hour=1, minute=00)

    semaphore = asyncio.Semaphore(10)
    session = AsyncMock()
    session.post.side_effect = Exception("Network error")

    notifier = SlackNotifier(
        semaphore=semaphore,
        session=session,
        notification=notification,
        changes=["114e2218-49c5-43fe-bcd7-18a1adc17a25"],
        changes_details=change_details,
        period={
            "start": pendulum.datetime(2024, 1, 1, 1, 0, tz="UTC"),
            "end": pendulum.datetime(2024, 1, 1, 2, 0, tz="UTC").subtract(seconds=1),
        },
    )

    with patch("includes.notifiers.KB_LOCAL_REPO", repo.repo_path):
        await notifier.execute()

    # Should complete without raising despite the exception
    session.post.assert_called()


def test_slack_notifier_format_slack_blocks_max_blocks(tests_path, tmp_path_factory):
    """Test that Slack blocks are split when exceeding MAX_BLOCKS"""
    notification = {
        "project_name": "test-project",
        "organization_name": "test-org",
        "notification_name": "test-notif",
        "project_subscriptions": ["foo"],
        "notification_conf": {
            "extras": {
                "webhook_url": "https://hooks.slack.com/webhook",
            }
        },
    }

    # Create many changes to exceed MAX_BLOCKS
    change_details = {}
    for i in range(30):  # Should create enough blocks to exceed MAX_BLOCKS=50
        change_id = f"change_{i}"
        change_details[change_id] = {
            "change_id": change_id,
            "change_path": "0001/CVE-2024-6962.v1.json",
            "cve_vendors": ["foo"],
            "cve_id": f"CVE-2024-{i:04d}",
            "cve_metrics": {},
        }

    repo = TestRepo("changes", tests_path, tmp_path_factory)
    repo.commit(["0001/CVE-2024-6962.v1.json"], hour=1, minute=00)

    notifier = SlackNotifier(
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

    with patch("includes.notifiers.KB_LOCAL_REPO", repo.repo_path):
        messages = notifier.format_slack_blocks()

    assert isinstance(messages, list)
    # Each message should have at most MAX_BLOCKS blocks
    for message in messages:
        assert len(message["blocks"]) <= SlackNotifier.MAX_BLOCKS
