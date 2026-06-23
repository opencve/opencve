from unittest import mock

from django.core import mail
from django.test import override_settings

from projects import notifications as notif


def test_build_mock_payload_uses_fixed_subscriptions_and_cves():
    """Build payload with fixed airflow/django subscriptions and 2 CVEs."""
    tester = notif.WebhookNotificationTester(
        extras={},
        project_name="myproject",
        organization_name="myorga",
        notification_name="mynotification",
        project_subscriptions=["ignored", "values"],
    )
    payload = tester.build_mock_payload()

    assert payload["subscriptions"]["raw"] == ["airflow", "django"]
    assert payload["matched_subscriptions"]["raw"] == ["airflow", "django"]
    assert len(payload["changes"]) == 2
    assert payload["changes"][0]["cve"]["cve_id"] == "CVE-2026-30911"
    assert payload["changes"][1]["cve"]["cve_id"] == "CVE-2025-64459"


@override_settings(WEB_BASE_URL="https://app.opencve.io")
def test_build_email_context_contains_scheduler_like_links():
    """Build email context with notification and project URLs."""
    tester = notif.EmailNotificationTester(
        extras={"email": "user@example.com"},
        project_name="myproject",
        organization_name="myorga",
        notification_name="mynotification",
        triggered_by_email="owner@example.com",
    )

    payload = tester.build_mock_payload()
    context = tester.build_email_context(payload)

    assert context["web_url"] == "https://app.opencve.io"
    assert context["project_url"].endswith("/org/myorga/projects/myproject")
    assert context["notification_url"].endswith(
        "/org/myorga/projects/myproject/notifications/mynotification"
    )
    assert context["created_by_email"] == "owner@example.com"


@override_settings(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    WEB_BASE_URL="https://app.opencve.io",
)
def test_email_notification_tester_sends_multipart_email():
    """Send one test email with plain and HTML alternatives."""
    mail.outbox.clear()
    tester = notif.EmailNotificationTester(
        extras={"email": "recipient@example.com"},
        project_name="myproject",
        organization_name="myorga",
        notification_name="mynotification",
    )

    result = tester.run()

    assert result.success is True
    assert len(mail.outbox) == 1
    message = mail.outbox[0]
    assert message.to == ["recipient@example.com"]
    assert len(message.alternatives) == 1
    assert message.alternatives[0].mimetype == "text/html"


def test_webhook_notification_tester_requires_url():
    """Return a clear error when webhook URL is missing."""
    tester = notif.WebhookNotificationTester(extras={})
    result = tester.run()
    assert result.success is False
    assert result.summary == "Webhook URL is required."


@override_settings(
    WEB_BASE_URL="https://app.opencve.io",
)
def test_slack_format_matches_scheduler_style():
    """Format Slack blocks with emoji, clickable CVEs and inline metadata."""
    tester = notif.SlackNotificationTester(
        extras={"webhook_url": "https://example.com"}
    )
    payload = tester.build_mock_payload()
    message = tester.build_slack_payload(payload)
    first_texts = [
        block["text"]["text"]
        for block in message["blocks"]
        if block.get("type") == "section"
    ]
    combined = "\n".join(first_texts)

    assert "🔴 *CRITICAL Severity*" in combined
    assert "*<https://app.opencve.io/cve/CVE-2025-64459|CVE-2025-64459>*" in combined
    assert "*CVSS:*" in combined
    assert " | *Events:* " in combined
    assert " | *Subscriptions:* " in combined


def test_run_notification_try_returns_error_for_unknown_type():
    """Return a failure result for unsupported notification type."""
    result = notif.run_notification_try("teams", extras={})
    assert result.success is False
    assert "Try is not implemented" in result.summary


def test_http_post_json_rejects_internal_url_without_network_call():
    """Reject internal URLs before any outbound HTTP request is made."""
    with mock.patch("opencve.utils.ssrf.requests.Session.request") as mock_request:
        result = notif._http_post_json("http://127.0.0.1:59999/internal", {"a": 1})

    mock_request.assert_not_called()
    assert result["success"] is False
    assert "private or reserved" in result["summary"]
    assert "error" in result["details"]


@mock.patch("projects.notifications.safe_request")
def test_http_post_json_returns_full_response_details(mock_safe_request):
    """Return status, headers and body in details for a successful public webhook call."""
    mock_response = mock.Mock()
    mock_response.status_code = 200
    mock_response.headers = {"X-Webhook": "ok"}
    mock_response.text = '{"received": true}'
    mock_safe_request.return_value = mock_response

    result = notif._http_post_json(
        "https://example.com/webhook",
        {"hello": "world"},
        headers={"Authorization": "Bearer secret"},
    )

    assert result["success"] is True
    assert result["summary"] == "HTTP 200"
    assert result["details"]["response_status"] == 200
    assert result["details"]["response_headers"]["X-Webhook"] == "ok"
    assert result["details"]["response_body"] == '{"received": true}'
    assert result["details"]["request_headers"]["Authorization"] == "[REDACTED]"
    mock_safe_request.assert_called_once()


@mock.patch("projects.notifications.safe_request")
def test_webhook_notification_tester_blocks_internal_url(mock_safe_request):
    """Surface SSRF validation errors when the webhook Try targets an internal URL."""
    mock_safe_request.side_effect = notif.UnsafeURL(
        "URL targets a private or reserved address"
    )

    tester = notif.WebhookNotificationTester(
        extras={"url": "http://127.0.0.1:59999/internal", "headers": {}},
    )
    result = tester.run()

    assert result.success is False
    assert "private or reserved" in result.summary
    assert result.details["error"] == "URL targets a private or reserved address"


@mock.patch("projects.notifications.safe_request")
def test_slack_notification_tester_returns_response_body(mock_safe_request):
    """Return the Slack webhook response body and status in Try result details."""
    mock_response = mock.Mock()
    mock_response.status_code = 200
    mock_response.headers = {"Content-Type": "text/plain"}
    mock_response.text = "ok"
    mock_safe_request.return_value = mock_response

    tester = notif.SlackNotificationTester(
        extras={"webhook_url": "https://hooks.slack.com/services/T/B/x"},
    )
    result = tester.run()

    assert result.success is True
    assert result.details["response_body"] == "ok"
    assert result.details["response_status"] == 200
