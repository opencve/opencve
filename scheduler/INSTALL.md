# OpenCVE Scheduler

The OpenCVE scheduler uses Airflow to periodically executes DAGs.

## Installation

Use a virtualenv:

```
cd scheduler
python3.11 -m venv venv && source venv/bin/activate && pip install pip --upgrade
```

First install Apache Airflow:

```
AIRFLOW_VERSION=2.8.1
PYTHON_VERSION="$(python --version | cut -d " " -f 2 | cut -d "." -f 1-2)"
CONSTRAINT_URL="https://raw.githubusercontent.com/apache/airflow/constraints-${AIRFLOW_VERSION}/constraints-${PYTHON_VERSION}.txt"

pip install "apache-airflow==${AIRFLOW_VERSION}" --constraint "${CONSTRAINT_URL}"
```

Then install the DAGs dependencies:

```
pip install -r requirements.txt
```

You have to export `AIRFLOW_HOME` env variable in order to specify folder you cloned the repo, for instance:

```
export AIRFLOW_HOME=/home/opencve/scheduler
```

The first execution of Airflow will create the `airflow.cfg` file, so launch this command for instance:

```
airflow version
```

You can now copy the `airflow.cfg.example` file:

```
cp airflow.cfg.example airflow.cfg
```

And customize it:

```
[core]
executor = LocalExecutor
load_examples = False

[database]
sql_alchemy_conn = postgresql+psycopg2://localhost:5432/opencve_scheduler

[opencve]
...
```

You also have to [generate a new fernet key](https://airflow.apache.org/docs/apache-airflow/stable/security/secrets/fernet.html#generating-fernet-key) and save it in the conf:

```
fernet_key = ywvTuNQw6bW-UlEyS0ykTqiz9on1cyMlHT7e1Ddo060=
```

You can now init the DB and create the fist admin:

```
airflow db migrate
airflow users create --username jdoe --firstname John --lastname Doe --role Admin --email jdoe@example.com
```

The connection to the OpenCVE database has to be created in the `opencve_postgres` conn_id:

```
airflow connections add opencve_postgres --conn-uri postgres://localhost:5432/opencve_web
airflow connections add opencve_redis --conn-uri redis://localhost:6379 --conn-extra '{"db": 3}'
```

You can finally launch the components:

```
airflow webserver -p 8080
airflow scheduler
```
