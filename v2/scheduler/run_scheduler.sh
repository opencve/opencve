source venv/bin/activate
export AIRFLOW_HOME=`pwd`
export SQLALCHEMY_SILENCE_UBER_WARNING=1
airflow scheduler

