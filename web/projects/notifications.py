import json
import logging
from datetime import datetime, timedelta
from abc import ABC, abstractmethod
from urllib.parse import quote
from urllib import error as urllib_error
from urllib import request as urllib_request

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils import timezone

logger = logging.getLogger(__name__)

DEFAULT_TRY_TIMEOUT_SEC = 30


def _try_timeout_seconds():
    return int(getattr(settings, "NOTIFICATION_TRY_TIMEOUT", DEFAULT_TRY_TIMEOUT_SEC))


SEVERITY_COLORS = {
    "critical": "#972b1e",
    "high": "#dd4b39",
    "medium": "#f39c12",
    "low": "#00c0ef",
    "none": "#c4c4c4",
}


class NotificationTryResult:
    """Structured result shown in the notification form after Try."""

    def __init__(self, success, channel_type, summary, details=None):
        self.success = success
        self.channel_type = channel_type
        self.summary = summary
        self.details = details or {}

    def as_template_dict(self):
        return {
            "success": self.success,
            "channel_type": self.channel_type,
            "summary": self.summary,
            "details": self.details,
        }


def _http_post_json(
    url,
    payload,
    headers=None,
):
    """
    POST JSON to URL using stdlib only. Returns a dict suitable for details.
    """
    body = json.dumps(payload).encode("utf-8")
    req_headers = {"Content-Type": "application/json", **(headers or {})}
    req = urllib_request.Request(
        url,
        data=body,
        headers=req_headers,
        method="POST",
    )
    timeout = _try_timeout_seconds()
    details = {
        "request_method": "POST",
        "request_url": url,
        "request_headers": dict(req_headers),
        "request_payload": json.dumps(payload, indent=2),
    }
    try:
        with urllib_request.urlopen(req, timeout=timeout) as resp:
            resp_body = resp.read().decode("utf-8", errors="replace")
            details["response_status"] = resp.status
            details["response_headers"] = dict(resp.headers.items())
            details["response_body"] = resp_body
            success = 200 <= resp.status < 300
            return {
                "success": success,
                "summary": (
                    f"HTTP {resp.status}"
                    if success
                    else f"Unexpected HTTP status {resp.status}"
                ),
                "details": details,
            }
    except urllib_error.HTTPError as e:
        try:
            resp_body = e.read().decode("utf-8", errors="replace")
        except Exception:
            resp_body = ""
        details["response_status"] = e.code
        details["response_headers"] = dict(e.headers.items()) if e.headers else {}
        details["response_body"] = resp_body
        return {
            "success": False,
            "summary": f"HTTP {e.code}",
            "details": details,
        }
    except urllib_error.URLError as e:
        details["error"] = str(e.reason) if e.reason else str(e)
        return {
            "success": False,
            "summary": f"Connection error: {details['error']}",
            "details": details,
        }
    except TimeoutError:
        details["error"] = f"Request timed out after {timeout}s"
        return {
            "success": False,
            "summary": details["error"],
            "details": details,
        }
    except Exception as e:
        logger.exception("Unexpected error during notification HTTP test")
        details["error"] = str(e)
        return {
            "success": False,
            "summary": str(e),
            "details": details,
        }


class BaseNotificationTester(ABC):
    """Base class for per-channel test sends."""

    channel_type = ""

    def __init__(
        self,
        extras,
        *,
        project_name="",
        organization_name="",
        notification_name="Test notification",
        project_subscriptions=None,
        triggered_by_email="",
    ):
        self.extras = extras
        self.project_name = project_name
        self.organization_name = organization_name
        self.notification_name = notification_name
        self.project_subscriptions = project_subscriptions or []
        self.triggered_by_email = triggered_by_email

    @abstractmethod
    def run(self):
        raise NotImplementedError

    def build_mock_payload(self):
        now = timezone.now()
        period_start = now - timedelta(hours=1)
        subscriptions = ["airflow", "django"]

        changes = [
            {
                "cve": {
                    "cve_id": "CVE-2026-30911",
                    "description": (
                        "Apache Airflow versions 3.1.0 through 3.1.7 missing "
                        "authorization vulnerability in the Execution API's "
                        "Human-in-the-Loop (HITL) endpoints that allows any "
                        "authenticated task instance to read, approve, or reject HITL "
                        "workflows belonging to any other task instance."
                    ),
                    "cvss31": 8.1,
                    "title": "Apache Airflow: Execution API HITL Endpoints Missing Per-Task Authorization",
                    "subscriptions": {
                        "raw": ["airflow"],
                        "human": ["Airflow"],
                    },
                },
                "events": [
                    {
                        "type": "cpes",
                        "details": {
                            "added": ["cpe:2.3:a:apache:airflow:*:*:*:*:*:*:*:*"],
                            "removed": [],
                        },
                    },
                    {
                        "type": "title",
                        "details": {
                            "new": "Apache Airflow: Execution API HITL Endpoints Missing Per-Task Authorization",
                            "old": None,
                        },
                    },
                    {
                        "type": "weaknesses",
                        "details": {"added": ["CWE-862"], "removed": []},
                    },
                    {
                        "type": "references",
                        "details": {
                            "added": [
                                "http://www.openwall.com/lists/oss-security/2026/03/17/2",
                                "https://github.com/apache/airflow/pull/62886",
                                "https://lists.apache.org/thread/1rs2v7fcko2otl6n9ytthcj87cmsgx51",
                            ],
                            "removed": [],
                        },
                    },
                    {
                        "type": "metrics",
                        "details": {
                            "added": {
                                "cvssV3_1": {
                                    "score": 8.1,
                                    "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                                }
                            },
                            "removed": {},
                            "updated": {},
                        },
                    },
                ],
            },
            {
                "cve": {
                    "cve_id": "CVE-2025-64459",
                    "description": (
                        "An issue was discovered in 5.1 before 5.1.14, 4.2 before "
                        "4.2.26, and 5.2 before 5.2.8. The methods QuerySet.filter(), "
                        "QuerySet.exclude(), and QuerySet.get(), and the class Q(), are "
                        "subject to SQL injection when using a suitably crafted "
                        "dictionary, with dictionary expansion, as the _connector "
                        "argument. Earlier, unsupported Django series (such as 5.0.x, "
                        "4.1.x, and 3.2.x) were not evaluated and may also be affected. "
                        "Django would like to thank cyberstan for reporting this issue."
                    ),
                    "cvss31": 9.1,
                    "title": "Potential SQL injection via _connector keyword argument in QuerySet and Q objects",
                    "subscriptions": {
                        "raw": ["django"],
                        "human": ["Django"],
                    },
                },
                "events": [
                    {
                        "type": "references",
                        "details": {
                            "added": [
                                "https://github.com/django/django/commit/c880530ddd4fabd5939bab0e148bebe36699432a",
                                "https://nvd.nist.gov/vuln/detail/CVE-2025-64459",
                                "https://www.cve.org/CVERecord?id=CVE-2025-64459",
                            ],
                            "removed": [],
                        },
                    },
                    {
                        "type": "cpes",
                        "details": {
                            "added": ["cpe:2.3:a:djangoproject:django:*:*:*:*:*:*:*:*"],
                            "removed": [],
                        },
                    },
                    {
                        "type": "metrics",
                        "details": {
                            "added": {
                                "cvssV3_1": {
                                    "score": 9.1,
                                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                                }
                            },
                            "removed": {},
                            "updated": {},
                        },
                    },
                ],
            },
        ]

        matched_raw = sorted(
            {sub for change in changes for sub in change["cve"]["subscriptions"]["raw"]}
        )
        payload = {
            "organization": self.organization_name,
            "project": self.project_name,
            "notification": self.notification_name,
            "subscriptions": {
                "raw": subscriptions,
                "human": ["Airflow", "Django"],
            },
            "matched_subscriptions": {
                "raw": matched_raw,
                "human": ["Airflow", "Django"],
            },
            "title": "2 changes on Airflow, Django",
            "period": {
                "start": period_start.isoformat(),
                "end": now.isoformat(),
            },
            "changes": changes,
        }
        return payload

    def build_email_context(self, payload):
        start = datetime.fromisoformat(payload["period"]["start"])
        end = datetime.fromisoformat(payload["period"]["end"])
        web_url = getattr(settings, "OPENCVE_WEB_URL", "http://localhost:8000")
        project_url = f"{web_url}/org/{quote(payload['organization'])}/projects/{quote(payload['project'])}"
        notification_url = (
            f"{project_url}/notifications/{quote(payload['notification'])}"
        )
        vulnerabilities = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "none": [],
        }
        severity_by_cve = {
            "CVE-2026-30911": "high",
            "CVE-2025-64459": "critical",
        }
        for change in payload["changes"]:
            score = change["cve"]["cvss31"]
            severity = severity_by_cve.get(change["cve"]["cve_id"], "none")
            vulnerabilities[severity].append(
                {
                    "cve_id": change["cve"]["cve_id"],
                    "description": change["cve"]["description"],
                    "subscriptions": change["cve"]["subscriptions"]["human"],
                    "score": float(score) if score is not None else None,
                    "changes": [e["type"] for e in change["events"]],
                    "severity": severity,
                    "severity_color": SEVERITY_COLORS[severity],
                }
            )

        return {
            "title": payload["title"],
            "total": len(payload["changes"]),
            "web_url": web_url,
            "project_url": project_url,
            "notification_url": notification_url,
            "unsubscribe_url": "",
            "created_by_email": self.triggered_by_email,
            "organization": payload["organization"],
            "project": payload["project"],
            "notification": payload["notification"],
            "period": {
                "day": start.strftime("%Y-%m-%d"),
                "from": start.strftime("%H:%M"),
                "to": end.strftime("%H:%M"),
            },
            "severity_colors": SEVERITY_COLORS,
            "vulnerabilities": vulnerabilities,
            "year": timezone.now().year,
            "triggered_by_email": self.triggered_by_email,
            "matched_subscriptions": payload["matched_subscriptions"]["human"],
        }


class EmailNotificationTester(BaseNotificationTester):
    channel_type = "email"

    def run(self):
        email_to = self.extras.get("email")
        if not email_to:
            return NotificationTryResult(
                success=False,
                channel_type=self.channel_type,
                summary="No email address configured.",
            )

        subject_prefix = getattr(settings, "ACCOUNT_EMAIL_SUBJECT_PREFIX", "[OpenCVE] ")
        payload = self.build_mock_payload()
        context = self.build_email_context(payload)
        subject = (
            f"{subject_prefix}[{self.project_name or 'project'}] {payload['title']}"
        )
        body = render_to_string("projects/emails/notification_try.txt", context)
        body_html = render_to_string("projects/emails/notification_try.html", context)

        from_email = getattr(settings, "DEFAULT_FROM_EMAIL", None)
        msg = EmailMultiAlternatives(
            subject=subject,
            body=body,
            from_email=from_email,
            to=[email_to],
        )
        msg.attach_alternative(body_html, "text/html")

        details = {
            "recipient": email_to,
            "subject": subject,
            "request_payload": json.dumps(payload, indent=2),
        }
        try:
            msg.send(fail_silently=False)
        except Exception as e:
            logger.exception("Failed to send test notification email")
            details["error"] = str(e)
            return NotificationTryResult(
                success=False,
                channel_type=self.channel_type,
                summary=f"Failed to send email: {e}",
                details=details,
            )

        details["status"] = "sent"
        return NotificationTryResult(
            success=True,
            channel_type=self.channel_type,
            summary=f"Test email sent to {email_to}.",
            details=details,
        )


class WebhookNotificationTester(BaseNotificationTester):
    channel_type = "webhook"

    def run(self):
        url = self.extras.get("url")
        headers = self.extras.get("headers") or {}
        if not isinstance(headers, dict):
            headers = {}
        if not url:
            return NotificationTryResult(
                success=False,
                channel_type=self.channel_type,
                summary="Webhook URL is required.",
            )

        payload = self.build_mock_payload()
        # urllib needs str header values
        str_headers = {str(k): str(v) for k, v in headers.items()}
        out = _http_post_json(url, payload, str_headers)
        return NotificationTryResult(
            success=out["success"],
            channel_type=self.channel_type,
            summary=out["summary"],
            details=out["details"],
        )


class SlackNotificationTester(BaseNotificationTester):
    channel_type = "slack"

    def build_slack_payload(self, source_payload):
        title = source_payload["title"]
        organization = source_payload["organization"]
        project = source_payload["project"]
        web_url = getattr(settings, "OPENCVE_WEB_URL", "https://app.opencve.io").rstrip(
            "/"
        )
        return {
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"🔔 *{title}*\n_{organization} / {project}_",
                    },
                },
                {"type": "divider"},
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "🔴 *CRITICAL Severity* — 1 CVE(s)",
                    },
                },
                {"type": "divider"},
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*<{web_url}/cve/CVE-2025-64459|CVE-2025-64459>*\n"
                            "*CVSS:* 9.1 | *Events:* cpes, metrics, references | *Subscriptions:* Django\n"
                            "An issue was discovered in 5.1 before 5.1.14, 4.2 before 4.2.26, and 5.2 before "
                            "5.2.8. The methods QuerySet.filter(), QuerySet.exclude(), and QuerySet.get(), and "
                            "the class Q(), are subject to SQL injection when using a suitably crafted dictionary, "
                            "with dictionary expansion, as the _connector argument. Earlier, unsupported Django "
                            "series (such as 5.0.x, 4.1.x, and 3.2.x) were not evaluated and may a…"
                        ),
                    },
                },
                {"type": "divider"},
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "🟠 *HIGH Severity* — 1 CVE(s)",
                    },
                },
                {"type": "divider"},
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*<{web_url}/cve/CVE-2026-30911|CVE-2026-30911>*\n"
                            "*CVSS:* 8.1 | *Events:* cpes, metrics, references, title, weaknesses | *Subscriptions:* Airflow\n"
                            "Apache Airflow versions 3.1.0 through 3.1.7 missing authorization vulnerability in "
                            "the Execution API's Human-in-the-Loop (HITL) endpoints that allows any authenticated "
                            "task instance to read, approve, or reject HITL workflows belonging to any other task instance."
                        ),
                    },
                },
                {"type": "divider"},
            ]
        }

    def run(self):
        webhook_url = self.extras.get("webhook_url")
        if not webhook_url:
            return NotificationTryResult(
                success=False,
                channel_type=self.channel_type,
                summary="Slack webhook URL is required.",
            )

        source_payload = self.build_mock_payload()
        payload = self.build_slack_payload(source_payload)
        out = _http_post_json(
            webhook_url,
            payload,
            {"Content-Type": "application/json"},
        )
        return NotificationTryResult(
            success=out["success"],
            channel_type=self.channel_type,
            summary=out["summary"],
            details={
                **out["details"],
                "source_payload": json.dumps(source_payload, indent=2),
            },
        )


NOTIFICATION_TRY_REGISTRY = {
    "email": EmailNotificationTester,
    "webhook": WebhookNotificationTester,
    "slack": SlackNotificationTester,
}


def run_notification_try(
    notification_type,
    extras,
    *,
    project_name="",
    organization_name="",
    notification_name="Test notification",
    project_subscriptions=None,
    triggered_by_email="",
):
    """
    Dispatch to the registered tester for notification_type.
    """
    cls = NOTIFICATION_TRY_REGISTRY.get(notification_type)
    if not cls:
        return NotificationTryResult(
            success=False,
            channel_type=notification_type,
            summary=f"Try is not implemented for channel type “{notification_type}”.",
        )
    tester = cls(
        extras,
        project_name=project_name,
        organization_name=organization_name,
        notification_name=notification_name,
        project_subscriptions=project_subscriptions,
        triggered_by_email=triggered_by_email,
    )
    return tester.run()
