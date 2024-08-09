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

    def prepare_payload(self):
        start = arrow.get(self.period.get("start")).to("utc").datetime.isoformat()
        end = arrow.get(self.period.get("end")).to("utc").datetime.isoformat()
        payload = {
            "organization": self.notification["organization_name"],
            "project": self.notification["project_name"],
            "notification": self.notification["notification_name"],
            "period": {
                "start": start,
                "end": end,
            },
            "changes": [],
        }

        for change in self.changes:

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
                    },
                    "events": kb_change[0]["data"] if kb_change else [],
                }
            )

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

    async def send(self):
        logger.info(
            "Sending %s notification to %s (%s changes)",
            self.type,
            self.url,
            str(len(self.changes)),
        )

        try:
            async with self.session.post(
                self.url, json=self.prepare_payload(), timeout=self.request_timeout
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

        # Prepare the Jinja2 templating used to send the mail
        dags_folder = pathlib.Path(conf.get("core", "dags_folder"))
        env = Environment(
            loader=FileSystemLoader(dags_folder / "templates"),
            autoescape=select_autoescape(),
            enable_async=True,
        )

        # Generate the messages to send
        context = self.get_template_context()
        message = MIMEMultipart("alternative")
        message["From"] = conf.get("opencve", "notification_smtp_mail_from")
        message["To"] = self.email
        message["Subject"] = (
            f"[{context['project']}] {context['total']} vulnerabilities found"
        )

        plain_text_template = env.get_template("email_notification.txt")
        plain_text_rendered = await plain_text_template.render_async(**context)
        plain_text_message = MIMEText(plain_text_rendered, "plain", "utf-8")

        html_template = env.get_template("email_notification.html")
        html_rendered = await html_template.render_async(**context)
        html_message = MIMEText(html_rendered, "html", "utf-8")

        message.attach(plain_text_message)
        message.attach(html_message)

        try:
            kwargs = {
                "hostname": conf.get("opencve", "notification_smtp_host"),
                "port": conf.getint("opencve", "notification_smtp_port"),
                "use_tls": conf.getboolean("opencve", "notification_smtp_use_tls"),
                "validate_certs": conf.getboolean(
                    "opencve", "notification_smtp_validate_certs"
                ),
                "timeout": conf.getint("opencve", "notification_smtp_timeout"),
            }

            # Support empty values for username and password
            username = conf.get("opencve", "notification_smtp_user")
            if username:
                kwargs["username"] = username

            password = conf.get("opencve", "notification_smtp_password")
            if password:
                kwargs["password"] = password

            response = await aiosmtplib.send(message, **kwargs)
        except aiosmtplib.errors.SMTPException as e:
            logger.error("SMTPException(%s): %s", self.email, e)
        except Exception as e:
            logger.error("Exception(%s): %s", self.email, e)
        else:
            logger.info("Result(%s): %s", self.email, response[1])
