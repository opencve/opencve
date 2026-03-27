import asyncio
import json
import logging
import urllib.parse
import datetime

import aiohttp
import aiosmtplib
import arrow
from airflow.configuration import conf

from includes.constants import KB_LOCAL_REPO
from includes.utils import get_smtp_conf, get_smtp_message

logger = logging.getLogger(__name__)


class BaseNotifier:
    type = None

    SEVERITY_COLORS = {
        "critical": "#972b1e",
        "high": "#dd4b39",
        "medium": "#f39c12",
        "low": "#00c0ef",
        "none": "#c4c4c4",
    }

    def __init__(
        self,
        *args,
        semaphore,
        session,
        notification,
        changes,
        changes_details,
        period,
        scheduled_report=None,
    ):
        self.semaphore = semaphore
        self.session = session
        self.notification = notification
        self.config = notification["notification_conf"]
        self.period = period
        self.scheduled_report = scheduled_report
        self.request_timeout = conf.getint("opencve", "notification_request_timeout")

        # Filter full list of changes details with the notification ones
        self.changes = [
            dict(changes_details[c]) for c in changes if c in changes_details
        ]

    @staticmethod
    def humanize_subscription(name):
        if "$PRODUCT$" in name:
            name = name.split("$PRODUCT$")[1]
        return " ".join(map(lambda x: x.capitalize(), name.split("_")))

    @staticmethod
    def humanize_subscriptions(subscriptions):
        return [BaseNotifier.humanize_subscription(s) for s in subscriptions]

    @staticmethod
    def get_title(payload):
        if payload.get("scheduled_report"):
            total = payload["scheduled_report"].get("cve_count", 0)
            period_type = payload["scheduled_report"].get("period_type", "period")
            return f"Scheduled {period_type} report ready ({total} CVEs)"

        total = len(payload["changes"])
        change_str = "changes" if total > 1 else "change"
        title = "{count} {change_str} on {subscriptions}".format(
            count=total,
            change_str=change_str,
            subscriptions=", ".join(payload["matched_subscriptions"]["human"]),
        )
        return title

    def prepare_payload(self):
        start = arrow.get(self.period.get("start")).to("utc").datetime.isoformat()
        end = arrow.get(self.period.get("end")).to("utc").datetime.isoformat()
        subscriptions = self.notification.get("project_subscriptions", [])

        payload = {
            "organization": self.notification["organization_name"],
            "project": self.notification["project_name"],
            "notification": self.notification["notification_name"],
            "subscriptions": {
                "raw": sorted(subscriptions),
                "human": sorted(self.humanize_subscriptions(subscriptions)),
            },
            "matched_subscriptions": {"raw": set(), "human": []},
            "title": None,
            "period": {
                "start": start,
                "end": end,
            },
            "changes": [],
        }

        for change in self.changes:
            # Compare the vendors between the CVE and the project subscriptions
            matched_subscriptions = list(
                set(subscriptions).intersection(change["cve_vendors"])
            )
            payload["matched_subscriptions"]["raw"].update(matched_subscriptions)

            # Get the CVE data from KB
            with open(KB_LOCAL_REPO / change["change_path"]) as f:
                cve_data = json.load(f)

            # Extract the wanted change
            kb_changes = cve_data["opencve"]["changes"]
            kb_change = [c for c in kb_changes if c["id"] == change["change_id"]]

            # CVE score
            score = None
            if cve_data["opencve"]["metrics"]["cvssV3_1"]["data"]:
                score = cve_data["opencve"]["metrics"]["cvssV3_1"]["data"]["score"]

            payload["changes"].append(
                {
                    "cve": {
                        "cve_id": change["cve_id"],
                        "description": cve_data["opencve"]["description"]["data"],
                        "cvss31": score,
                        "subscriptions": {
                            "raw": sorted(matched_subscriptions),
                            "human": sorted(
                                self.humanize_subscriptions(matched_subscriptions)
                            ),
                        },
                    },
                    "events": kb_change[0]["data"] if kb_change else [],
                }
            )

        # Transform the matched_subscriptions set into a list
        payload["matched_subscriptions"]["raw"] = sorted(
            list(payload["matched_subscriptions"]["raw"])
        )
        payload["matched_subscriptions"]["human"] = sorted(
            self.humanize_subscriptions(payload["matched_subscriptions"]["raw"])
        )

        # Prepare the title
        payload["title"] = self.get_title(payload)

        return payload

    def prepare_scheduled_report_payload(self):
        start = arrow.get(self.period.get("start")).to("utc").datetime.isoformat()
        end = arrow.get(self.period.get("end")).to("utc").datetime.isoformat()
        scheduled = self.scheduled_report or {}
        payload = {
            "organization": self.notification["organization_name"],
            "project": self.notification["project_name"],
            "notification": self.notification["notification_name"],
            "period": {"start": start, "end": end},
            "scheduled_report": scheduled,
            "title": self.get_title({"scheduled_report": scheduled}),
        }
        return payload

    @staticmethod
    def get_severity_str(score):
        if not score:
            severity = "none"
        elif 0.0 <= score <= 3.9:
            severity = "low"
        elif 4.0 <= score <= 6.9:
            severity = "medium"
        elif 7.0 <= score <= 8.9:
            severity = "high"
        elif 9.0 <= score <= 10.0:
            severity = "critical"
        else:
            severity = "none"
        return severity

    async def execute(self):
        async with self.semaphore:
            logger.debug("List of changes: %s", self.changes)
            return await self.send()

    async def send(self):
        raise NotImplementedError()


class WebhookNotifier(BaseNotifier):
    type = "webhook"

    def __init__(self, *args, **kwargs):
        super().__init__(self, *args, **kwargs)
        self.url = self.config.get("extras").get("url")
        self.headers = self.config.get("extras").get("headers", {})

    async def send(self):
        logger.info(
            "Sending %s notification to %s (%s changes)",
            self.type,
            self.url,
            str(len(self.changes)),
        )
        payload = (
            self.prepare_scheduled_report_payload()
            if self.scheduled_report
            else self.prepare_payload()
        )

        try:
            async with self.session.post(
                self.url,
                json=payload,
                headers=self.headers,
                timeout=self.request_timeout,
            ) as response:
                response_text = await response.text()
                response_headers = dict(response.headers)
                status_code = response.status
        except aiohttp.ClientConnectorError as e:
            logger.error("ClientConnectorError(%s): %s", self.url, e)
            return {
                "status": "failed",
                "details": {
                    "summary": str(e),
                    "request_headers": self.headers,
                    "request_payload": json.dumps(payload),
                },
            }
        except aiohttp.ClientResponseError as e:
            logger.error("ClientResponseError(%s): %s", self.url, e)
            return {
                "status": "failed",
                "details": {
                    "summary": str(e),
                    "status_code": e.status,
                    "request_headers": self.headers,
                    "request_payload": json.dumps(payload),
                },
            }
        except asyncio.TimeoutError:
            logger.error(
                "TimeoutError(%s): the request timeout of %s has been exceeded",
                self.url,
                f"{str(self.request_timeout)} seconds",
            )
            return {
                "status": "failed",
                "details": {
                    "summary": "Request timed out",
                    "request_headers": self.headers,
                    "request_payload": json.dumps(payload),
                },
            }
        except Exception as e:
            logger.error("Exception(%s): %s", self.url, e)
            return {
                "status": "failed",
                "details": {
                    "summary": str(e),
                    "request_headers": self.headers,
                    "request_payload": json.dumps(payload),
                },
            }
        else:
            logger.info("Result(%s): %s", self.url, status_code)
            logger.debug("Response(%s): %s", self.url, response_text)
            return {
                "status": "success" if 200 <= status_code < 300 else "failed",
                "details": {
                    "response_url": self.url,
                    "status_code": status_code,
                    "request_headers": self.headers,
                    "request_payload": json.dumps(payload),
                    "response_headers": response_headers,
                    "response_body": response_text,
                },
            }


class SlackNotifier(BaseNotifier):
    type = "slack"
    MAX_BLOCKS = 50

    def __init__(self, *args, **kwargs):
        super().__init__(self, *args, **kwargs)
        self.webhook_url = self.config.get("extras").get("webhook_url")

    def format_slack_blocks(self):
        if self.scheduled_report:
            return self.format_slack_blocks_scheduled()
        payload = self.prepare_payload()
        title = payload["title"]
        organization = payload["organization"]
        project = payload["project"]

        # Group changes by CVE ID
        cves = {}
        for change in payload["changes"]:
            cve = change["cve"]
            cve_id = cve["cve_id"]
            if cve_id not in cves:
                score = float(cve["cvss31"]) if cve["cvss31"] else None
                severity = self.get_severity_str(score)
                cves[cve_id] = {
                    "cve_id": cve_id,
                    "score": score,
                    "severity": severity,
                    "desc": (
                        (cve["description"][:400] + "…")
                        if len(cve["description"]) > 400
                        else cve["description"]
                    ),
                    "subscriptions": ", ".join(cve["subscriptions"]["human"]),
                    "events": set(),
                }
            cves[cve_id]["events"].update(e["type"] for e in change["events"])

        # Group CVEs by severity
        severities = ["critical", "high", "medium", "low", "none"]
        grouped = {s: [] for s in severities}
        for cve in cves.values():
            grouped[cve["severity"]].append(cve)

        # Build all blocks
        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"🔔 *{title}*\n_{organization} / {project}_",
                },
            },
            {"type": "divider"},
        ]

        for severity in severities:
            if not grouped[severity]:
                continue
            emoji = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🟢",
                "none": "⚪️",
            }[severity]
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"{emoji} *{severity.upper()} Severity* — {len(grouped[severity])} CVE(s)",
                    },
                }
            )
            blocks.append({"type": "divider"})

            for cve in grouped[severity]:
                text = (
                    f"*<https://app.opencve.io/cve/{cve['cve_id']}|{cve['cve_id']}>*\n"
                    f"*CVSS:* {cve['score'] or 'N/A'} | "
                    f"*Events:* {', '.join(cve['events']) or 'None'} | "
                    f"*Subscriptions:* {cve['subscriptions']}\n"
                    f"{cve['desc']}"
                )
                blocks.append(
                    {"type": "section", "text": {"type": "mrkdwn", "text": text}}
                )
                blocks.append({"type": "divider"})

        # Split into messages if needed
        return [
            {"blocks": blocks[i : i + self.MAX_BLOCKS]}
            for i in range(0, len(blocks), self.MAX_BLOCKS)
        ]

    def format_slack_blocks_scheduled(self):
        payload = self.prepare_scheduled_report_payload()
        report = payload["scheduled_report"]
        title = payload["title"]
        organization = payload["organization"]
        project = payload["project"]
        period_label = report.get("report_day", "N/A")
        cve_count = report.get("cve_count", 0)
        report_url = report.get("report_url")
        timezone_label = report.get("period_timezone", "UTC")

        report_line = (
            f"<{report_url}|Open report>" if report_url else "Report link unavailable"
        )
        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"🗂️ *{title}*\n_{organization} / {project}_",
                },
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*Period:* {period_label} ({timezone_label})\n"
                        f"*Total CVEs:* {cve_count}\n"
                        f"*Report:* {report_line}"
                    ),
                },
            },
        ]
        return [{"blocks": blocks}]

    async def send(self):
        logger.info("Sending Slack notification to %s", self.webhook_url)
        messages = self.format_slack_blocks()
        responses = []
        has_error = False

        for idx, msg in enumerate(messages, 1):
            try:
                async with self.session.post(
                    self.webhook_url,
                    json=msg,
                    headers={"Content-Type": "application/json"},
                    timeout=self.request_timeout,
                ) as resp:
                    text = await resp.text()
                    responses.append(
                        {
                            "index": idx,
                            "status_code": resp.status,
                            "response_body": text,
                        }
                    )
                    if resp.status != 200:
                        has_error = True
                        logger.error(
                            "Slack message %s/%s failed: %s %s",
                            idx,
                            len(messages),
                            resp.status,
                            text,
                        )
                    else:
                        logger.info(
                            "Slack message %s/%s sent (%s blocks)",
                            idx,
                            len(messages),
                            len(msg["blocks"]),
                        )
            except Exception as e:
                has_error = True
                responses.append(
                    {"index": idx, "status_code": None, "response_body": str(e)}
                )
                logger.error(
                    "Error sending Slack message %s/%s: %s", idx, len(messages), e
                )
        last_response = responses[-1] if responses else {}
        return {
            "status": "failed" if has_error else "success",
            "details": {
                "response_url": self.webhook_url,
                "status_code": last_response.get("status_code"),
                "request_headers": {"Content-Type": "application/json"},
                "request_payload": json.dumps(messages[-1]) if messages else None,
                "response_body": json.dumps(responses),
            },
        }


class EmailNotifier(BaseNotifier):
    type = "email"

    def __init__(self, *args, **kwargs):
        super().__init__(self, *args, **kwargs)
        self.email = self.config.get("extras").get("email")

    def get_template_context(self):
        if self.scheduled_report:
            return self.get_scheduled_template_context()

        payload = super().prepare_payload()
        organization = payload["organization"]
        project = payload["project"]
        notification = payload["notification"]

        web_url = conf.get("opencve", "web_base_url")
        project_url = f"{web_url}/org/{urllib.parse.quote(organization)}/projects/{urllib.parse.quote(project)}"
        notification_url = (
            f"{project_url}/notifications/{urllib.parse.quote(notification)}"
        )
        extras = self.config.get("extras") or {}
        unsubscribe_token = extras.get("unsubscribe_token")
        unsubscribe_url = (
            f"{web_url}/notifications/unsubscribe/{unsubscribe_token}"
            if unsubscribe_token
            else ""
        )

        context = {
            "web_url": web_url,
            "project_url": project_url,
            "notification_url": notification_url,
            "unsubscribe_url": unsubscribe_url,
            "created_by_email": extras.get("created_by_email") or "",
            "title": payload["title"],
            "total": len(payload["changes"]),
            "organization": organization,
            "project": project,
            "notification": notification,
            "period": {
                "day": arrow.get(payload["period"]["start"]).strftime("%Y-%m-%d"),
                "from": arrow.get(payload["period"]["start"]).strftime("%H:%M"),
                "to": arrow.get(payload["period"]["end"]).strftime("%H:%M"),
            },
            "severity_colors": self.SEVERITY_COLORS,
            "vulnerabilities": {
                "critical": [],
                "high": [],
                "medium": [],
                "low": [],
                "none": [],
            },
            "year": datetime.datetime.now().year,
        }

        for change in payload["changes"]:
            score = float(change["cve"]["cvss31"]) if change["cve"]["cvss31"] else None
            cve = {
                "cve_id": change["cve"]["cve_id"],
                "description": change["cve"]["description"],
                "subscriptions": change["cve"]["subscriptions"]["human"],
                "score": score,
                "changes": [e["type"] for e in change["events"]],
            }

            # Sort the vulnerability by its score
            severity = self.get_severity_str(score)
            context["vulnerabilities"][severity].append(cve)

        return context

    def get_scheduled_template_context(self):
        payload = self.prepare_scheduled_report_payload()
        report = payload["scheduled_report"]
        organization = payload["organization"]
        project = payload["project"]
        notification = payload["notification"]
        extras = self.config.get("extras") or {}
        web_url = conf.get("opencve", "web_base_url")
        project_url = f"{web_url}/org/{urllib.parse.quote(organization)}/projects/{urllib.parse.quote(project)}"
        notification_url = (
            f"{project_url}/notifications/{urllib.parse.quote(notification)}"
        )

        unsubscribe_token = extras.get("unsubscribe_token")
        unsubscribe_url = (
            f"{web_url}/notifications/unsubscribe/{unsubscribe_token}"
            if unsubscribe_token
            else ""
        )

        return {
            "web_url": web_url,
            "project_url": project_url,
            "notification_url": notification_url,
            "unsubscribe_url": unsubscribe_url,
            "created_by_email": extras.get("created_by_email") or "",
            "title": payload["title"],
            "organization": organization,
            "project": project,
            "notification": notification,
            "report_url": report.get("report_url", ""),
            "period_label": report.get("report_day", ""),
            "period_type": report.get("period_type", "daily"),
            "period_timezone": report.get("period_timezone", "UTC"),
            "cve_count": report.get("cve_count", 0),
            "year": datetime.datetime.now().year,
        }

    async def send(self):
        logger.info(
            "Sending %s notification to %s (%s changes)",
            self.type,
            self.email,
            str(len(self.changes)),
        )

        context = self.get_template_context()
        template_name = (
            "email_scheduled_report" if self.scheduled_report else "email_notification"
        )
        message = await get_smtp_message(
            email_to=self.email,
            subject=f"[{context['project']}] {context['title']}",
            template=template_name,
            context=context,
        )

        try:
            kwargs = get_smtp_conf()
            response = await aiosmtplib.send(message, **kwargs)
        except aiosmtplib.errors.SMTPException as e:
            logger.error("SMTPException(%s): %s", self.email, e)
            return {
                "status": "failed",
                "details": {
                    "summary": str(e),
                    "status": "failed",
                    "response_body": str(e),
                },
            }
        except Exception as e:
            logger.error("Exception(%s): %s", self.email, e)
            return {
                "status": "failed",
                "details": {
                    "summary": str(e),
                    "status": "failed",
                    "response_body": str(e),
                },
            }
        else:
            logger.info("Result(%s): %s", self.email, response[1])
            return {
                "status": "success",
                "details": {
                    "status": "delivered",
                    "response_body": str(response[1]),
                },
            }
