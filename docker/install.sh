#!/bin/bash
#
# This script initializes the environment to bootstrap OpenCVE stack and starts it
# Run is as root or via sudo

set -e

add-config-files() {

    echo "--> Adding Airflow configuration file"
    cp ../scheduler/airflow.cfg.example ../scheduler/airflow.cfg

    echo "--> Adding Django settings and .env file"
    cp ../web/opencve/conf/settings.py.example ../web/opencve/conf/settings.py
    cp ../web/opencve/conf/.env.example ../web/opencve/conf/.env

    echo "--> Copying .env file for docker compose"
    cp ./conf/.env.example ./.env

    echo "--> Copying opencve.conf.template for Nginx"
    cp ./conf/opencve.conf.template.example ./conf/opencve.conf.template

    echo ""
    echo "/!\ Don't forget to update the .env and settings.py files with your inputs before starting the docker compose stack:"
    echo ""
    echo "Docker .env: ./.env"
    echo "Webserver .env: ../web/opencve/conf/.env"
    echo "Django settings: ../web/opencve/conf/settings.py"
    echo "Airflow settings: ../scheduler/airflow.cfg"
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

    echo "--> Updating OpenCVE secret key"
    export OPENCVE_SECRET_KEY=$(docker exec -it webserver python manage.py generate_secret_key)
    sed -i.bak "s/OPENCVE_SECRET_KEY=.*/OPENCVE_SECRET_KEY=$OPENCVE_SECRET_KEY/g" ../web/opencve/conf/.env && rm -f ../web/opencve/conf/.env.bak

    unset POSTGRES_USER
    unset POSTGRES_PASSWORD
    unset OPENCVE_SECRET_KEY

    echo "--> Restarting webserver"
    docker restart webserver

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

    echo "--> Get PG ENV variables from docker compose env file"
    export $(grep -v '^#' .env | grep 'POSTGRES' | xargs -d '\n')

    echo "--> Confirm the new user"
    docker exec -it postgres psql -U $POSTGRES_USER  -c 'INSERT INTO account_emailaddress(email, verified, "primary", user_id) SELECT email, 1::bool, 1::bool, id FROM opencve_users ON CONFLICT (user_id, email) DO NOTHING;';

    unset POSTGRES_USER
    unset POSTGRES_PASSWORD

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
