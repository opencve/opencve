#!/bin/bash
#
# This script initializes the environment to bootstrap OpenCVE stack and starts it
# Run is as root or via sudo

set -e

set-user() {

    echo "--> Creating airflow user"

    if id airflow; then
        # Check user id
        if [ "$(id -u airflow)" -eq 50000 ]; then
            echo "User airflow already setup"
        else
            echo "User airflow has not the correct id, expected: 50000"
            exit 1
        fi
    else
        # Add user airflow
        useradd -m airflow -u 50000
    fi

    # Create airflow directories with airflow user
    echo "--> Creating airflow directories"
    su - airflow -c 'test -d ~/repositories' || su - airflow -c 'mkdir ~/repositories'
    su - airflow -c 'test -d ~/logs' || su - airflow -c 'mkdir ~/logs'
    su - airflow -c 'test -d ~/test' || su - airflow -c 'mkdir ~/test'
    echo "Done"

}

clone-repositories() {

    echo "--> Cloning OpenCVE needed repositories"
    su - airflow -c 'git clone https://github.com/opencve/opencve-kb.git ~/repositories/opencve-kb'
    su - airflow -c 'git clone https://github.com/opencve/opencve-nvd.git ~/repositories/opencve-nvd'
    su - airflow -c 'git clone https://github.com/CVEProject/cvelistV5.git ~/repositories/cvelistV5'

}

add-config-files() {

    echo "--> Adding airflow config file"
    cp ../scheduler/airflow.cfg /home/airflow/airflow.cfg
    chown airflow:airflow /home/airflow/airflow.cfg

    echo "--> Adding Django settings file"
    cp ../web/opencve/settings.py ./settings.py

    echo "--> Copying .env file for docker compose"
    cp ./samples/env.sample ./.env

    echo "Don't forget to update the .env and settings.py files with your inputs before starting the docker compose stack"

}

start-docker-stack() {

    echo "--> Starting Docker compose stack"
    docker compose up -d

    echo "--> Adding Airflow connections"
    docker exec -it airflow-scheduler airflow connections add opencve_postgres --conn-uri postgres://opencve:opencve@postgres:5432/opencve
    docker exec -it airflow-scheduler airflow connections add opencve_redis --conn-uri redis://redis:6379 --conn-extra '{"db": 3}'
    docker exec -it airflow-scheduler airflow connections list

    echo "--> Collecting static files from Django webserver"
    docker exec -it opencve-webserver python manage.py collectstatic

    echo "--> Django webserver DB migrate"
    docker exec -it opencve-webserver python manage.py migrate

    echo "--> Creating superuser on OpenCVE"
    docker exec -it opencve-webserver python manage.py createsuperuser

}

import-opencve-kb() {

    echo "--> Importing OpenCVE KB inside the database, this can take 15 to 30min."
    docker exec -it opencve-webserver python manage.py importdb

}

start-opencve-dag() {

    echo "--> Unpausing the dag"
    docker exec -it airflow-scheduler airflow dags unpause opencve

}

display-usage() {
    echo "Usage: install.sh OPTIONS"
    echo ""
    echo "Example: ./install.sh prepare"
    echo ""
    echo "OPTIONS:"
    echo ""
    echo " prepare : Run set-user & clone-repositories & add-config-files"
    echo " start   : Run start-docker-stack & import-opencve-kb & start-opencve-dag"
    echo ""
    echo ""
    echo "Specific OPTIONS:"
    echo ""
    echo " set-user           : Install airflow user"
    echo " clone-repositories : Clone KB repositories"
    echo " add-config-files   : Add default configurations files"
    echo " start-docker-stack : Start docker compose stack"
    echo " import-opencve-kb  : Import OpenCVE KB inside local database"
    echo " start-opencve-dag  : Unpause OpenCVE Dag in Airflow"
    echo ""
    echo ""
}


_OPTIONS=$1

case $_OPTIONS in
    "prepare" )
        set-user
        clone-repositories
        add-config-files
        ;;
    "start" )
        start-docker-stack
        import-opencve-kb
        start-opencve-dag
        ;;
    "set-user" )
        set-user
        ;;
    "clone-repositories" )
        clone-repositories
        ;;
    "add-config-files" )
        add-config-files
        ;;
     "start-docker-stack" )
        start-docker-stack
        ;;
     "import-opencve-kb" )
        import-opencve-kb
        ;;
     "start-opencve-dag" )
        start-opencve-dag
        ;;
    * )
        display-usage
        ;;
esac

