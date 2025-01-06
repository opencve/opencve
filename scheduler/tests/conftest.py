import json
import os
import pathlib

import pendulum
import pytest

# AIRFLOW_HOME has to be defined before airflow imports
AIRFLOW_HOME = os.path.dirname(os.path.dirname(__file__))
os.environ["AIRFLOW_HOME"] = AIRFLOW_HOME

from airflow import DAG
from airflow.providers.postgres.hooks.postgres import PostgresHook
from airflow.providers.redis.hooks.redis import RedisHook
from airflow.utils import db as airflow_db
from airflow.utils.state import DagRunState
from airflow.utils.types import DagRunType

# Override Airflow configuration during tests
os.environ["AIRFLOW__DATABASE__LOAD_DEFAULT_CONNECTIONS"] = "False"
os.environ["AIRFLOW__CORE__LOAD_EXAMPLES"] = "False"
os.environ["AIRFLOW__CORE__UNIT_TEST_MODE"] = "True"

os.environ["AIRFLOW__OPENCVE__WEB_BASE_URL"] = "https://app.opencve.io"
os.environ["AIRFLOW__OPENCVE__MITRE_REPO_PATH"] = AIRFLOW_HOME
os.environ["AIRFLOW__OPENCVE__ADVISORIES_REPO_PATH"] = AIRFLOW_HOME
os.environ["AIRFLOW__OPENCVE__KB_REPO_PATH"] = AIRFLOW_HOME
os.environ["AIRFLOW__OPENCVE__NVD_REPO_PATH"] = AIRFLOW_HOME
os.environ["AIRFLOW__OPENCVE__VULNRICHMENT_REPO_PATH"] = AIRFLOW_HOME
os.environ["AIRFLOW__OPENCVE__REDHAT_REPO_PATH"] = AIRFLOW_HOME
os.environ["AIRFLOW__OPENCVE__START_DATE"] = "2024-01-01"
os.environ["AIRFLOW__OPENCVE__NOTIFICATION_REQUEST_TIMEOUT"] = "5"

os.environ["AIRFLOW__OPENCVE__DEVELOPMENT_MODE"] = "False"
os.environ["AIRFLOW_CONN_OPENCVE_POSTGRES"] = (
    "postgresql://opencve:opencve@localhost:5432/opencve"
)
os.environ["AIRFLOW_CONN_OPENCVE_REDIS"] = "redis://localhost:6379"


@pytest.fixture(autouse=True)
def process_markers(request, web_pg_hook, web_redis_hook):
    node = request.node

    # Reset Airflow database
    airflow_db_marker = node.get_closest_marker("airflow_db")
    if airflow_db_marker:
        airflow_db.resetdb()

    # Reset Web database
    web_db_marker = node.get_closest_marker("web_db")
    if web_db_marker:
        sql_query = (
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema='public' AND table_type='BASE TABLE';"
        )

        tables = [r[0] for r in web_pg_hook.get_records(sql_query)]
        web_pg_hook.run(f'TRUNCATE TABLE {",".join(tables)} RESTART IDENTITY CASCADE;')

    # Reset Redis database
    redis_db_marker = node.get_closest_marker("web_redis")
    if redis_db_marker:
        web_redis_hook.flushall()


@pytest.fixture(scope="session")
def web_pg_hook():
    return PostgresHook(postgres_conn_id="opencve_postgres")


@pytest.fixture(scope="session")
def web_redis_hook():
    return RedisHook(redis_conn_id="opencve_redis").get_conn()


@pytest.fixture(scope="session")
def tests_path():
    return pathlib.Path(__file__).parent.resolve()


@pytest.fixture(scope="function")
def open_file():
    def _open_file(name):
        with open(pathlib.Path(__file__).parent.resolve() / "data" / name) as f:
            return json.load(f)

    return _open_file


@pytest.fixture(scope="function")
def run_dag_task():
    def _run_dag_task(task_fn, start, end, params={}):
        with DAG(
            dag_id="opencve",
            schedule="@daily",
            start_date=pendulum.datetime(2024, 1, 1, tz="UTC"),
            params=params,
        ) as dag:
            task_fn(task_name=task_fn.function.__name__)

        dagrun = dag.create_dagrun(
            state=DagRunState.RUNNING,
            execution_date=start,
            data_interval=(start, end),
            start_date=start,
            run_type=DagRunType.MANUAL,
        )
        ti = dagrun.get_task_instance(task_id=task_fn.function.__name__)
        ti.task = dag.get_task(task_id=task_fn.function.__name__)
        ti.run(ignore_ti_state=True)
        return ti

    return _run_dag_task


@pytest.fixture(scope="function")
def override_conf():
    def _override_conf(section, key, value):
        full_key = f"AIRFLOW__{section.upper()}__{key.upper()}"
        os.environ[full_key] = value

    return _override_conf


@pytest.fixture(scope="function")
def override_confs(override_conf):
    def _override_confs(section, data):
        for key, value in data.items():
            override_conf(section, key, value)

    return _override_confs
