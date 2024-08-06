#!/bin/bash
#
# This script initializes the environment to bootstrap OpenCVE stack and starts it
# Run is as root or via sudo

set -e

add-config-files() {

    echo "--> Adding Airflow configuration file"
    cp ../scheduler/airflow.cfg.example ../scheduler/airflow.cfg

    echo "--> Adding Django settings file"
    cp ../web/opencve/settings.py.example ../web/opencve/settings.py

    echo "--> Copying .env file for docker compose"
    cp ./config/env.example ./.env

    echo "--> Copying opencve.conf.template for Nginx"
    cp ./config/opencve.conf.template.example ./config/opencve.conf.template

    echo ""
    echo "/!\ Don't forget to update the .env and settings.py files with your inputs before starting the docker compose stack"
    echo ""

}

set-airflow-start-date() {
    echo "--> Configuring start_start in Airflow configuration file for today"
    sed -i.bak "s/start_date = .*/start_date = $(date '+%Y-%m-%d')/g" ../scheduler/airflow.cfg && rm -f ../scheduler/airflow.cfg.bak
    grep "start_date" ../scheduler/airflow.cfg
}

start-docker-stack() {

    echo "--> Get PG ENV variables from docker compose env file"
    export $(grep -v '^#' .env | grep 'POSTGRES' | xargs -d '\n')

    echo "--> Starting Docker compose stack"
    docker compose up -d

    echo "--> Adding Airflow connections"
    docker exec -it airflow-scheduler airflow connections add opencve_postgres --conn-uri postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@postgres:5432/opencve
    docker exec -it airflow-scheduler airflow connections add opencve_redis --conn-uri redis://redis:6379 --conn-extra '{"db": 3}'
    docker exec -it airflow-scheduler airflow connections list

    echo "--> Collecting static files from Django webserver"
    docker exec -it webserver python manage.py collectstatic

    echo "--> Django webserver DB migrate"
    docker exec -it webserver python manage.py migrate

}

clone-repositories() {

    echo "--> Cloning OpenCVE needed repositories"
    docker exec -it airflow-scheduler git clone https://github.com/opencve/opencve-kb.git /home/airflow/repositories/opencve-kb
    docker exec -it airflow-scheduler git clone https://github.com/opencve/opencve-nvd.git /home/airflow/repositories/opencve-nvd
    docker exec -it airflow-scheduler git clone https://github.com/opencve/opencve-redhat.git /home/airflow/repositories/opencve-redhat
    docker exec -it airflow-scheduler git clone https://github.com/CVEProject/cvelistV5.git /home/airflow/repositories/cvelistV5
    docker exec -it airflow-scheduler git clone https://github.com/cisagov/vulnrichment.git /home/airflow/repositories/vulnrichment

}

create-superuser() {

     echo "--> Creating superuser on OpenCVE"
     docker exec -it webserver python manage.py createsuperuser

}

import-opencve-kb() {

    echo "--> Importing OpenCVE KB inside the database, this can take 15 to 30min."
    docker exec -it webserver python manage.py import_cves

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
    echo " prepare : add-config-files & set-airflow-start-date"
    echo " start   : Run start-docker-stack & clone-repositories & create-superuser & import-opencve-kb & start-opencve-dag"
    echo ""
    echo ""
    echo "Specific OPTIONS:"
    echo ""
    echo " add-config-files       : Add default configurations files"
    echo " set-airflow-start-date : Configure Airflow start date"
    echo " start-docker-stack     : Start docker compose stack"
    echo " clone-repositories     : Clone KB repositories"
    echo " create-superuser       : Create OpenCVE super user with admin privileges"
    echo " import-opencve-kb      : Import OpenCVE KB inside local database"
    echo " start-opencve-dag      : Unpause OpenCVE Dag in Airflow"
    echo ""
    echo ""
}


_OPTIONS=$1

case $_OPTIONS in
    "prepare" )
        add-config-files
        set-airflow-start-date
        ;;
    "start" )
        start-docker-stack
        clone-repositories
        create-superuser
        import-opencve-kb
        start-opencve-dag
        ;;
    "clone-repositories" )
        clone-repositories
        ;;
    "add-config-files" )
        add-config-files
        ;;
     "set-airflow-start-date" )
        set-airflow-start-date
        ;;
     "start-docker-stack" )
        start-docker-stack
        ;;
     "create-superuser" )
        create-superuser
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

