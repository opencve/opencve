import logging

from airflow.decorators import task
from airflow.exceptions import AirflowSkipException
from airflow.providers.postgres.hooks.postgres import PostgresHook
from airflow.providers.redis.hooks.redis import RedisHook

from constants import SQL_PROJECT_WITH_NOTIFICATIONS
from includes.tasks import get_start_end_dates
from utils import get_project_notifications

logger = logging.getLogger(__name__)


@task
def get_notifications(**context):
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    postgres_hook = PostgresHook(postgres_conn_id="opencve_postgres")
    start, end = get_start_end_dates(context)

    # Get the list of projects
    projects = redis_hook.json().objkeys(f"subscriptions_{start}_{end}")
    if not projects:
        raise AirflowSkipException(f"No project from {start} to {end}")

    # Get the notifications and group them by project
    records = postgres_hook.get_records(
        sql=SQL_PROJECT_WITH_NOTIFICATIONS,
        parameters={"projects": tuple(projects)}
    )
    notifications = get_project_notifications(records)
    if not notifications:
        raise AirflowSkipException("No notifications found")

    # Save the result in redis
    key = f"notifications_{start}_{end}"
    redis_hook.json().set(key, "$", notifications)
    redis_hook.expire(key, 60 * 60 * 24)


@task
def send_notifications():
    pass
