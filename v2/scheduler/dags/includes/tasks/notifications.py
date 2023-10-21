import logging

from airflow.decorators import task

logger = logging.getLogger(__name__)


@task
def send_reports():
    pass


@task
def send_notifications():
    pass
