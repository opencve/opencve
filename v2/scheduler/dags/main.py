"""import logging
import pendulum
from airflow.providers.postgres.hooks.postgres import PostgresHook
from airflow.configuration import conf
from airflow.decorators import dag, task

from utils import get_chunks
from tasks import git_pull


logger = logging.getLogger(__name__)

@dag(
    schedule="0 * * * *",
    start_date=pendulum.datetime(2023, 1, 1, tz="UTC"),
    catchup=False,
    max_active_runs=1,
)
def sources():
    @task
    def handle_projects(projects):
        print("---- C'EST PARTI ----")
        print(len(projects))
    @task
    def populate_reports_chunked():
        logger.info("Listing projects")
        hook = PostgresHook(postgres_conn_id="opencve_postgres")
        projects = hook.get_records(
            sql="SELECT id, name, subscriptions FROM opencve_projects"
        )
        logger.info(f"Got {len(projects)} projects")

        # We can't create more than `max_map_length` mapped tasks,
        # so we distribute the projects into chunks.
        max_map_length = conf.getint("core", "max_map_length")
        chunks = get_chunks(projects, max_map_length)

        logger.info(f"Launching {len(chunks)} mapped tasks")
        handle_projects.expand(projects=chunks)

    git_pull() >> analyse_changes() >> save_cves_vendors() >> populate_reports()

sources()"""
