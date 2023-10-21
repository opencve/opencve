import logging

import pendulum
from airflow.decorators import dag
from airflow.utils.task_group import TaskGroup

from constants import SQL_CHANGE_WITH_VENDORS, SQL_PROJECT_WITH_SUBSCRIPTIONS
from includes.operators.fetcher_operator import FetcherOperator
from includes.operators.parser_operator import ParserOperator
from includes.operators.select_operator import SelectOperator
from tasks.reports import populate_reports, get_subscriptions, get_changes
from utils import get_project_subscriptions, get_vendor_changes

"""from tasks.notifications import send_notifications, send_reports
from tasks.reports import get_changes, get_subscriptions, populate_reports"""


logger = logging.getLogger(__name__)


@dag(
    schedule="0 * * * *",
    start_date=pendulum.datetime(2023, 1, 1, tz="UTC"),
    catchup=False,
    max_active_runs=1,
)
def updater():
    with TaskGroup(group_id="fetchers") as fetch_group:
        _ = [
            FetcherOperator(task_id="fetch_mitre", kind="mitre"),
            FetcherOperator(task_id="fetch_nvd", kind="nvd"),
        ]

    with TaskGroup(group_id="parsers") as parse_group:
        _ = [
            ParserOperator(task_id="parse_mitre", kind="mitre"),
            ParserOperator(task_id="parse_nvd", kind="nvd"),
        ]

    with TaskGroup(group_id="reports") as reports_group:
        get_subscriptions() >> get_changes() >> populate_reports()
        """vendor_changes = SelectOperator(
            task_id="vendor_changes",
            query=SQL_CHANGE_WITH_VENDORS,
            reduce_fn=get_vendor_changes,
        )
        project_subscriptions = SelectOperator(
            task_id="project_subscriptions",
            query=SQL_PROJECT_WITH_SUBSCRIPTIONS,
            reduce_fn=get_project_subscriptions,
        )
        vendor_changes >> project_subscriptions >> populate_reports()"""

    """with TaskGroup(group_id="reports") as reports_group:
        _ = [get_changes(), get_subscriptions()] >> populate_reports()

    with TaskGroup(group_id="notifications") as notifications_group:
        _ = [send_reports(), send_notifications()]"""

    (
        fetch_group >> parse_group >> reports_group
    )  # >> reports_group >> notifications_group


updater()
