import asyncio
import importlib
import logging

import aiohttp
from airflow.configuration import conf
from airflow.decorators import task
from airflow.exceptions import AirflowSkipException
from airflow.providers.postgres.hooks.postgres import PostgresHook
from airflow.providers.redis.hooks.redis import RedisHook
from includes.constants import SQL_PROJECT_WITH_NOTIFICATIONS
from includes.utils import (
    divide_list,
    group_notifications_by_project,
    get_dates_from_context,
)

logger = logging.getLogger(__name__)


@task
def prepare_notifications(**context):
    start, end = get_dates_from_context(context)

    # Get the list of subscriptions
    subscriptions_redis_key = f"subscriptions_{start}_{end}"
    logger.info(
        "Fetching subscriptions between %s and %s using Redis (key: %s)",
        start,
        end,
        subscriptions_redis_key,
    )
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    subscriptions = redis_hook.json().get(subscriptions_redis_key)
    logger.info("Found %s subscriptions", str(len(subscriptions)))

    # Get the notifications and group them by project
    logger.info("Listing notifications in %s table", "opencve_notifications")
    postgres_hook = PostgresHook(postgres_conn_id="opencve_postgres")
    records = postgres_hook.get_records(
        sql=SQL_PROJECT_WITH_NOTIFICATIONS,
        parameters={"projects": tuple(subscriptions.keys())},
    )
    notifications = group_notifications_by_project(records, subscriptions)
    if not notifications:
        raise AirflowSkipException("No notification found")

    # Save the result in redis
    notifications_key = f"notifications_{start}_{end}"
    logger.info(
        "Found %s notifications, saving it in Redis (key: %s)",
        str(len(notifications)),
        notifications_key,
    )
    redis_hook.json().set(notifications_key, "$", notifications)
    redis_hook.expire(notifications_key, 60 * 60 * 24)


async def execute_coroutines(notifications, change_details, period):
    max_notifications_per_task = conf.getint("opencve", "max_notifications_per_task")
    semaphore = asyncio.Semaphore(max_notifications_per_task)

    tasks = []
    async with aiohttp.ClientSession(raise_for_status=True) as session:
        for notification_data in notifications:
            logger.debug("Handling notification: %s", notification_data)
            notification = notification_data["notification"]

            notif_cls = getattr(
                importlib.import_module("includes.notifiers"),
                f"{notification['notification_type'].capitalize()}Notifier",
            )

            logger.debug("Executing %s method of %s", "send", notif_cls)
            tasks.append(
                asyncio.ensure_future(
                    notif_cls(
                        semaphore=semaphore,
                        session=session,
                        notification=notification,
                        changes=notification_data["changes"],
                        changes_details=change_details,
                        period=period,
                    ).execute()
                )
            )

        return await asyncio.gather(*tasks)


@task
def send_notifications(notifications, **context):
    logger.info("Found %s notifications to send", str(len(notifications)))
    logger.debug("Notifications list: %s", notifications)

    # Retrieve the list of change details
    start, end = get_dates_from_context(context)
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    changes_details_key = f"changes_details_{start}_{end}"
    changes_details = redis_hook.json().get(changes_details_key)
    logger.debug(f"{changes_details_key}: %s", changes_details)

    loop = asyncio.get_event_loop()
    result = loop.run_until_complete(
        execute_coroutines(notifications, changes_details, {"start": start, "end": end})
    )
    logger.debug("Notifications results: %s", result)
    return True


@task
def make_notifications_chunks(**context):
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    start, end = get_dates_from_context(context)
    logger.info("Checking notifications to send between %s and %s", start, end)

    project_changes_key = f"project_changes_{start}_{end}"
    project_changes = redis_hook.json().get(project_changes_key)
    logger.debug(f"{project_changes_key}: %s", project_changes)
    logger.info("Found %s projects with changes", str(len(project_changes)))

    changes_details_key = f"changes_details_{start}_{end}"
    changes_details = redis_hook.json().get(changes_details_key)
    logger.debug(f"{changes_details_key}: %s", changes_details)

    notifications_key = f"notifications_{start}_{end}"
    notifications = redis_hook.json().get(notifications_key)
    logger.debug(f"{notifications_key}: %s", notifications)

    # Iterate over all the projects and filter the changes to sent
    # based on notifications settings
    sending_notifications = []
    for project, changes in project_changes.items():
        # Avoid changes analysis if no notification
        if project not in notifications:
            continue

        project_notifications = notifications[project]
        logger.info(
            "Checking project %s with %s notification(s)",
            project,
            str(len(project_notifications)),
        )

        for idx, notification in enumerate(project_notifications):
            logger.info(
                "[%s] Parsing %s change(s) for notification %s",
                project,
                str(len(changes)),
                str(idx + 1),
            )

            # Check if notification rules keep changes or not
            filtered_changes = filter_changes(notification, changes, changes_details)
            logger.info(
                "[%s] Found %s change(s) matching the notification rules",
                project,
                str(len(filtered_changes)),
            )
            if not filtered_changes:
                continue

            # Changes have to be sent to the notification
            sending_notifications.append(
                {
                    "notification": notification,
                    "changes": filtered_changes,
                }
            )

    logger.info("Found %s notifications to send", str(len(sending_notifications)))

    # Distribute the notifications between mapped tasks
    max_notifications_map_length = conf.getint(
        "opencve", "max_notifications_map_length"
    )
    chunks = divide_list(sending_notifications, max_notifications_map_length)
    logger.debug(
        "Built %s chunks with max_notifications_map_length of %s",
        str(len(chunks)),
        str(max_notifications_map_length),
    )
    return chunks


def filter_changes(notification, changes, changes_details):
    notification_score = notification["notification_conf"]["metrics"]["cvss31"]
    notification_types = notification["notification_conf"]["types"]
    logger.debug(
        "Notification score: %s, types: %s", notification_score, notification_types
    )

    reduced_changes = []
    for change in changes:
        change_details = changes_details[change]
        change_score = change_details["cve_metrics"]["cvssV3_1"]["data"]
        change_types = change_details["change_types"]
        logger.debug(
            "Change %s: metrics: %s, types: %s", change, change_score, change_types
        )

        # Exclude change if CVSS31 score is lower than notification one
        if change_score and float(change_score["score"]) < float(notification_score):
            continue

        # Exclude change if types don't match notifications ones
        if not notification_types or not any(
            (True for x in notification_types if x in change_types)
        ):
            continue

        reduced_changes.append(change)

    return reduced_changes
