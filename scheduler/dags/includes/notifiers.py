import asyncio
import json
import logging
import pathlib
import urllib.parse


import aiohttp
import aiosmtplib
import arrow
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from airflow.configuration import conf
from jinja2 import Environment, FileSystemLoader, select_autoescape

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
        self, *args, semaphore, session, notification, changes, changes_details, period
    ):
        self.semaphore = semaphore
        self.session = session
        self.notification = notification
        self.config = notification["notification_conf"]
        self.period = period
        self.request_timeout = conf.getint("opencve", "notification_request_timeout")

        # Filter full list of changes details with the notification ones
        self.changes = [dict(changes_details[c]) for c in changes]

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

        try:
            async with self.session.post(
                self.url,
                json=self.prepare_payload(),
                headers=self.headers,
                timeout=self.request_timeout,
            ) as response:
                json_response = await response.json()
                status_code = response.status
        except aiohttp.ClientConnectorError as e:
            logger.error("ClientConnectorError(%s): %s", self.url, e)
        except aiohttp.ClientResponseError as e:
            logger.error("ClientResponseError(%s): %s", self.url, e)
        except asyncio.TimeoutError:
            logger.error(
                "TimeoutError(%s): the request timeout of %s has been exceeded",
                self.url,
                f"{str(self.request_timeout)} seconds",
            )
        except Exception as e:
            logger.error("Exception(%s): %s", self.url, e)
        else:
            logger.info("Result(%s): %s", self.url, status_code)
            logger.debug("Response(%s): %s", self.url, json_response)

        # No need to return the response we don't use it
        return {}


class EmailNotifier(BaseNotifier):
    type = "email"

    def __init__(self, *args, **kwargs):
        super().__init__(self, *args, **kwargs)
        self.email = self.config.get("extras").get("email")

    def get_template_context(self):
        payload = super().prepare_payload()
        organization = payload["organization"]
        project = payload["project"]
        notification = payload["notification"]

        web_url = conf.get("opencve", "web_base_url")
        project_url = f"{web_url}/org/{urllib.parse.quote(organization)}/projects/{urllib.parse.quote(project)}"
        notification_url = (
            f"{project_url}/notifications/{urllib.parse.quote(notification)}"
        )

        context = {
            "web_url": web_url,
            "project_url": project_url,
            "notification_url": notification_url,
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

    async def send(self):
        logger.info(
            "Sending %s notification to %s (%s changes)",
            self.type,
            self.email,
            str(len(self.changes)),
        )

        context = self.get_template_context()
        message = await get_smtp_message(
            email_to=self.email,
            subject=f"[{context['project']}] {context['title']}",
            template="email_notification",
            context=context,
        )

        try:
            kwargs = get_smtp_conf()
            response = await aiosmtplib.send(message, **kwargs)
        except aiosmtplib.errors.SMTPException as e:
            logger.error("SMTPException(%s): %s", self.email, e)
        except Exception as e:
            logger.error("Exception(%s): %s", self.email, e)
        else:
            logger.info("Result(%s): %s", self.email, response[1])
