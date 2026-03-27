import asyncio
import logging
import datetime

import aiosmtplib
from airflow.configuration import conf
from airflow.decorators import task
from airflow.exceptions import AirflowSkipException
from airflow.providers.postgres.hooks.postgres import PostgresHook

from includes.constants import SQL_REPORTS_WITH_NOTIFICATIONS
from includes.utils import get_smtp_conf, get_smtp_message

logger = logging.getLogger(__name__)


async def send_report_email(report_data):
    project_name = report_data["project_name"]
    org_name = report_data["org_name"]
    ai_summary = report_data["ai_summary"]
    day = report_data["day"]
    email_to = report_data["email"]
    notification_name = report_data["notification_name"]

    web_url = conf.get("opencve", "web_base_url")
    project_url = (
        f"{web_url}/org/{org_name}/projects/{project_name}/reports"
    )

    context = {
        "project": project_name,
        "organization": org_name,
        "ai_summary": ai_summary,
        "day": day,
        "web_url": web_url,
        "project_url": project_url,
        "year": datetime.datetime.now().year,
    }

    subject = f"[{project_name}] Daily Security Report - {day}"

    logger.info(
        "Sending report email to %s for project %s (notification: %s)",
        email_to,
        project_name,
        notification_name,
    )

    message = await get_smtp_message(
        email_to=email_to,
        subject=subject,
        template="email_report",
        context=context,
    )

    try:
        kwargs = get_smtp_conf()
        response = await aiosmtplib.send(message, **kwargs)
        logger.info("Report email sent to %s: %s", email_to, response[1])
    except aiosmtplib.errors.SMTPException as e:
        logger.error("SMTPException(%s): %s", email_to, e)
    except Exception as e:
        logger.error("Exception(%s): %s", email_to, e)


async def execute_report_emails(email_tasks):
    await asyncio.gather(*email_tasks)


@task
def send_report_notifications(**context):
    day = str(context["data_interval_start"].date())
    logger.info("Sending report notifications for day %s", day)

    hook = PostgresHook(postgres_conn_id="opencve_postgres")
    records = hook.get_records(
        sql=SQL_REPORTS_WITH_NOTIFICATIONS,
        parameters={"day": day},
    )

    if not records:
        raise AirflowSkipException("No reports with ai_summary found for %s" % day)

    logger.info("Found %s report notification(s) to send", len(records))

    email_tasks = []
    for record in records:
        report_id, project_id, project_name, org_name, ai_summary, notification_name, notification_conf = record
        extras = notification_conf.get("extras") or {}
        email_to = extras.get("email")

        if not email_to:
            logger.warning(
                "No email configured for notification %s (project %s), skipping",
                notification_name,
                project_name,
            )
            continue

        email_tasks.append(
            send_report_email({
                "project_name": project_name,
                "org_name": org_name,
                "ai_summary": ai_summary,
                "day": day,
                "email": email_to,
                "notification_name": notification_name,
            })
        )

    if not email_tasks:
        raise AirflowSkipException("No valid email addresses found in report notifications")

    loop = asyncio.get_event_loop()
    loop.run_until_complete(execute_report_emails(email_tasks))
    logger.info("Finished sending %s report email(s)", len(email_tasks))