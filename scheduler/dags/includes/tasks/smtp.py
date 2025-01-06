import logging
import asyncio

import aiosmtplib
from airflow.configuration import conf
from airflow.decorators import task

from includes.utils import get_smtp_conf, get_smtp_message


logger = logging.getLogger(__name__)


async def send_email(smtp_conf, email):
    logger.info("Sending test email to %s", email)

    message = await get_smtp_message(
        email_to=email,
        subject="SMTP Configuration Test for OpenCVE Scheduler",
        template="email_test",
        context={"web_url": conf.get("opencve", "web_base_url")},
    )

    await aiosmtplib.send(message, **smtp_conf)


@task
def run(params: dict, **context):
    email_to = params["email"]
    smtp_conf = get_smtp_conf()

    logger.info("Sending an email to %s", email_to)
    logger.info("Current configuration: %s", smtp_conf)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(send_email(smtp_conf, email_to))
    loop.close()

    logger.info("Email sent")
