import asyncio
import json
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import aiohttp
import aiosmtplib
import arrow
from airflow.configuration import conf
from includes.constants import KB_LOCAL_REPO

logger = logging.getLogger(__name__)


class BaseNotification:
    type = None

    def __init__(
        self, *args, semaphore, session, config, changes, changes_details, period
    ):
        self.semaphore = semaphore
        self.session = session
        self.config = config
        self.period = period
        self.request_timeout = conf.getint("opencve", "notification_request_timeout")

        # Filter full list of changes details with the notification ones
        self.changes = [dict(changes_details[c]) for c in changes]

    def prepare_payload(self):
        start = arrow.get(self.period.get("start")).to("utc").datetime.isoformat()
        end = arrow.get(self.period.get("end")).to("utc").datetime.isoformat()
        payload = {
            "period": {
                "start": start,
                "end": end,
            },
            "changes": [],
        }

        for change in self.changes:
            cve_id = change.pop("cve_id")

            # Get the CVE data from KB
            cve_kb = KB_LOCAL_REPO / cve_id.split("-")[1] / cve_id / f"{cve_id}.json"
            with open(cve_kb) as f:
                cve_data = json.load(f)
            cve_opencve_data = cve_data.get("opencve")

            # Get the change data from KB
            change_kb = KB_LOCAL_REPO / change["change_path"]
            with open(change_kb) as f:
                change_data = json.load(f)

            payload["changes"].append(
                {
                    "cve": {
                        "cve_id": cve_id,
                        "description": cve_opencve_data["description"],
                        "cvss31": cve_opencve_data["metrics"]["v31"].get("score"),
                    },
                    "events": change_data.get("events", []),
                }
            )

        return payload

    async def execute(self):
        async with self.semaphore:
            logger.debug("List of changes: %s", self.changes)
            return await self.send()

    async def send(self):
        raise NotImplementedError()


class WebhookNotification(BaseNotification):
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


class EmailNotification(BaseNotification):
    type = "email"

    def __init__(self, *args, **kwargs):
        super().__init__(self, *args, **kwargs)
        self.email = self.config.get("extras").get("email")

    async def send(self):
        logger.info(
            "Sending %s notification to %s (%s changes)",
            self.type,
            self.email,
            str(len(self.changes)),
        )
        message = MIMEMultipart("alternative")
        message["From"] = conf.get("opencve", "notification_smtp_mail_from")
        message["To"] = self.email
        message["Subject"] = "To complete"

        plain_text_message = MIMEText("To complete", "plain", "utf-8")
        html_message = MIMEText(
            "<html><body><h1>To complete</h1></body></html>", "html", "utf-8"
        )
        message.attach(plain_text_message)
        message.attach(html_message)

        try:
            response = await aiosmtplib.send(
                message,
                hostname=conf.get("opencve", "notification_smtp_host"),
                username=conf.get("opencve", "notification_smtp_user"),
                password=conf.get("opencve", "notification_smtp_password"),
                port=conf.getint("opencve", "notification_smtp_port"),
                use_tls=conf.getboolean("opencve", "notification_smtp_use_tls"),
                validate_certs=conf.getboolean(
                    "opencve", "notification_smtp_validate_certs"
                ),
                timeout=conf.getint("opencve", "notification_smtp_timeout"),
            )
        except aiosmtplib.errors.SMTPException as e:
            logger.error("SMTPException(%s): %s", self.email, e)
        except Exception as e:
            logger.error("Exception(%s): %s", self.email, e)
        else:
            logger.info("Result(%s): %s", self.email, response[1])
