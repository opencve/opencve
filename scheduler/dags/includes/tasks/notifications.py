import logging

from airflow.decorators import task
from airflow.providers.postgres.hooks.postgres import PostgresHook
from airflow.providers.redis.hooks.redis import RedisHook

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
    logger.info("Fetching projects with subscriptions between %s and %s using Redis (key: %s)", start, end, subscriptions_redis_key)
    projects = redis_hook.json().objkeys(subscriptions_redis_key)
    logger.info("Found %s projects with subscriptions", str(len(projects)))
    if not projects:
        return

    # Get the notifications and group them by project
    logger.info("Listing notifications in %s table for the associated projects", "opencve_notifications")
    records = postgres_hook.get_records(
        sql=SQL_PROJECT_WITH_NOTIFICATIONS,
        parameters={"projects": tuple(projects)}
    )
    notifications = get_project_notifications(records)
    if not notifications:
        logger.info("No notification found")
        return

    # Save the result in redis
    notifications_key = f"notifications_{start}_{end}"
    logger.info("Found %s notifications, saving it in Redis (key: %s)", str(len(notifications)), notifications_key)
    redis_hook.json().set(notifications_key, "$", notifications)
    redis_hook.expire(notifications_key, 60 * 60 * 24)


@task
def send_notifications():
    pass
