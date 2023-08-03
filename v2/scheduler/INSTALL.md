# OpenCVE Scheduler

The OpenCVE scheduler uses Airflow to periodically executes DAGs.

## Installation

Use a virtualenv:

```
python3 -m venv venv && source venv/bin/activate && pip install pip --upgrade
```

First install Apache Airflow (tested on my laptop with **Python 3.8.9**):

```
AIRFLOW_VERSION=2.5.3
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
export AIRFLOW_HOME=/Users/ncrocfer/Dev/opencve/v2/scheduler
```

To disable all Airflow warnings:

```
export SQLALCHEMY_SILENCE_UBER_WARNING=1
```

The first execution of Airflow will create the `airflow.cfg` file, so launch this command for instance:

```
airflow version
```

Some customizations can be done:

```
[core]
executor = LocalExecutor
load_examples = False

[database]
sql_alchemy_conn = postgresql+psycopg2://localhost:5432/opencve_airflow

[opencve]
nvd_repo_path = /Users/ncrocfer/Dev/nvd
mitre_repo_path = /Users/ncrocfer/Dev/cvelistV5
```

Note: the NVD and the MITRE repositories have been cloned in the web installation.

You also have to [generate a new fernet key](https://airflow.apache.org/docs/apache-airflow/stable/security/secrets/fernet.html#generating-fernet-key) and save it in the conf:

```
fernet_key = ywvTuNQw6bW-UlEyS0ykTqiz9on1cyMlHT7e1Ddo060=
```

You can now init the DB and create the fist admin:

```
airflow db init
airflow users create --username admin --firstname Amber --lastname Security --role Admin --email admin@local
```

You can finally launch the components:

```
airflow webserver -p 8080
airflow scheduler
```

The webserver listens on http://localhost:8080.

## DAGs

### Changes


