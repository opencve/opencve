import json
import os
import pathlib

from airflow.providers.postgres.hooks.postgres import PostgresHook
import pytest

AIRFLOW_HOME = os.path.dirname(os.path.dirname(__file__))

# Override Airflow configuration during tests
os.environ["AIRFLOW__DATABASE__LOAD_DEFAULT_CONNECTIONS"] = "False"
os.environ["AIRFLOW__CORE__LOAD_EXAMPLES"] = "False"
os.environ["AIRFLOW__CORE__UNIT_TEST_MODE"] = "True"
os.environ["AIRFLOW_HOME"] = AIRFLOW_HOME

os.environ["AIRFLOW__OPENCVE__MITRE_REPO_PATH"] = AIRFLOW_HOME
os.environ["AIRFLOW__OPENCVE__ADVISORIES_REPO_PATH"] = AIRFLOW_HOME
os.environ["AIRFLOW__OPENCVE__KB_REPO_PATH"] = AIRFLOW_HOME
os.environ["AIRFLOW__OPENCVE__NVD_REPO_PATH"] = AIRFLOW_HOME
os.environ["AIRFLOW__OPENCVE__VULNRICHMENT_REPO_PATH"] = AIRFLOW_HOME
os.environ["AIRFLOW__OPENCVE__REDHAT_REPO_PATH"] = AIRFLOW_HOME
os.environ["AIRFLOW__OPENCVE__START_DATE"] = "2024-01-01"

os.environ["AIRFLOW__OPENCVE__DEVELOPMENT_MODE"] = "False"
os.environ["AIRFLOW_CONN_OPENCVE_POSTGRES"] = "postgresql://localhost:5432/opencve_web_tests"


@pytest.fixture(autouse=True, scope="session")
def reset_db():
    from airflow.utils import db

    db.resetdb()
    yield


@pytest.fixture(scope="function")
def web_pg_hook():
    """This fixture is used to truncate the web database
    and return a PostgresHook object"""
    sql_query = ("SELECT table_name FROM information_schema.tables "
                 "WHERE table_schema='public' AND table_type='BASE TABLE';")
    hook = PostgresHook(postgres_conn_id="opencve_postgres")
    tables = [r[0] for r in hook.get_records(sql_query)]
    hook.run(f'TRUNCATE TABLE {",".join(tables)} RESTART IDENTITY CASCADE;')
    yield hook


@pytest.fixture(scope="session")
def tests_path():
    return pathlib.Path(__file__).parent.resolve()


@pytest.fixture(scope="function")
def open_file():
    def _open_file(name):
        with open(pathlib.Path(__file__).parent.resolve() / "data" / name) as f:
            return json.load(f)

    return _open_file
