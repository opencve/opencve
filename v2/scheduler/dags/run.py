import logging

import pendulum
from airflow.decorators import dag
from airflow.utils.task_group import TaskGroup

from tasks.fetchers import fetch_mitre, fetch_nvd
from tasks.parsers import parse_nvd, parse_mitre
from tasks.notifications import send_notifications, send_reports
from tasks.reports import get_changes, get_subscriptions, populate_reports


logger = logging.getLogger(__name__)


@dag(
    schedule="0 * * * *",
    start_date=pendulum.datetime(2023, 1, 1, tz="UTC"),
    catchup=False,
    max_active_runs=1,
)
def changes():
    with TaskGroup(group_id="fetchers") as fetch_group:
        _ = [fetch_mitre(), fetch_nvd()]

    with TaskGroup(group_id="parsers") as parse_group:
        _ = parse_mitre() >> parse_nvd()

    with TaskGroup(group_id="reports") as reports_group:
        _ = [get_changes(), get_subscriptions()] >> populate_reports()

    with TaskGroup(group_id="notifications") as notifications_group:
        _ = [send_reports(), send_notifications()]

    fetch_group >> parse_group >> reports_group >> notifications_group


changes()
