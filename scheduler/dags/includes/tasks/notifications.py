import logging

from airflow.decorators import task
from airflow.exceptions import AirflowSkipException
from airflow.providers.postgres.hooks.postgres import PostgresHook
from airflow.providers.redis.hooks.redis import RedisHook
from airflow.utils.email import send_email_smtp

from includes.constants import SQL_PROJECT_WITH_NOTIFICATIONS
from includes.utils import get_project_notifications, get_start_end_dates

logger = logging.getLogger(__name__)


@task
def list_notifications(**context):
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    postgres_hook = PostgresHook(postgres_conn_id="opencve_postgres")
    start, end = get_start_end_dates(context)

    # Get the list of subscriptions
    subscriptions_redis_key = f"subscriptions_{start}_{end}"
    logger.info("Fetching subscriptions between %s and %s using Redis (key: %s)", start, end, subscriptions_redis_key)
    subscriptions = redis_hook.json().objkeys(subscriptions_redis_key)
    logger.info("Found %s subscriptions", str(len(subscriptions)))

    # Get the notifications and group them by project
    logger.info("Listing notifications in %s table", "opencve_notifications")
    records = postgres_hook.get_records(
        sql=SQL_PROJECT_WITH_NOTIFICATIONS,
        parameters={"projects": tuple(subscriptions)}
    )
    notifications = get_project_notifications(records)
    if not notifications:
        raise AirflowSkipException("No notification found")

    # Save the result in redis
    notifications_key = f"notifications_{start}_{end}"
    logger.info("Found %s notifications, saving it in Redis (key: %s)", str(len(notifications)), notifications_key)
    redis_hook.json().set(notifications_key, "$", notifications)
    redis_hook.expire(notifications_key, 60 * 60 * 24)


@task
def send_notifications(**context):
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    start, end = get_start_end_dates(context)

    vendor_changes = redis_hook.json().get(f"vendor_changes_{start}_{end}")
    changes_details = redis_hook.json().get(f"changes_details_{start}_{end}")
    subscriptions = redis_hook.json().get(f"subscriptions_{start}_{end}")
    notifications = redis_hook.json().get(f"notifications_{start}_{end}")
    project_changes = redis_hook.json().get(f"project_changes_{start}_{end}")

    # Start by reducing the list of vendors
    print("vendor_changes")
    print(vendor_changes)
    print("changes_details")
    print(changes_details)
    print("subscriptions")
    print(subscriptions)
    print("notifications")
    print(notifications)
    print("project_changes")
    print(project_changes)

    for project, changes in project_changes.items():

        # Avoid changes analysis if no notification
        if project not in notifications:
            continue

        for notification in notifications[project]:
            filtered_changes = reduce_changes(notification, changes, changes_details)
            print("filtered changes")
            print(filtered_changes)
            #send_notification_changes(notification, filtered_changes)


def reduce_changes(notification, changes, changes_details):
    notification_score = notification["conf"]["cvss"]
    notification_events = notification["conf"]["events"]

    reduced_changes = []
    for change in changes:
        change_details = changes_details[change]

        # Exclude change if CVSS score is lower than notification one
        change_score = change_details["cve_metrics"]["v31"]
        if change_score and float(change_score["score"]) < float(notification_score):
            continue

        # Exclude change if events don't match notifications ones
        change_events = change_details["change_types"]
        if not notification_events or not any((True for x in notification_events if x in change_events)):
            continue

        reduced_changes.append(change)

    return reduced_changes


def send_notification_changes(notification, changes):
    return
    send_email_smtp(
        to="ncrocfer@gmail.com",
        subject="Hello from Airflow dev",
        html_content="<h1>Hello world</h1>",
    )

