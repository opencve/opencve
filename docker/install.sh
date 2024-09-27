#!/bin/bash
# The script sets up and initializes the environment for the OpenCVE stack.
# It handles configuration files, Docker services, database connections, & more.
# Each function in the script performs a distinct task, such as configuring
# files, starting services, cloning repositories, etc.
# Run as root or via sudo

set -e  # Exit immediately if any command fails

# Function to add configuration files for various components
add-config-files() {
    echo "INFO: Adding Airflow configuration file"
    cp ../scheduler/airflow.cfg.example ../scheduler/airflow.cfg

    echo "INFO: Adding Django settings and .env file"
    cp ../web/opencve/conf/settings.py.example ../web/opencve/conf/settings.py
    cp ../web/opencve/conf/.env.example ../web/opencve/conf/.env

    echo "INFO: Copying .env file for Docker Compose"
    cp ./conf/.env.example ./.env

    echo "INFO: Copying opencve.conf.template for Nginx"
    cp ./conf/opencve.conf.template.example ./conf/default.conf

    echo "INFO: Configuration files added successfully."
    echo "/!\\ Don't forget to update the .env and settings.py files with your inputs before starting the Docker Compose stack."
    echo "Docker .env: ./.env"
    echo "Webserver .env: ../web/opencve/conf/.env"
    echo "Django settings: ../web/opencve/conf/settings.py"
    echo "Airflow settings: ../scheduler/airflow.cfg"
}

# Function to set the start date for Airflow as the current date
set-airflow-start-date() {
    echo "INFO: Configuring start_date in Airflow for today's date"
    sed -i.bak "s/start_date = .*/start_date = $(date '+%Y-%m-%d')/g" ../scheduler/airflow.cfg && rm -f ../scheduler/airflow.cfg.bak
    grep "start_date" ../scheduler/airflow.cfg
    echo "INFO: Airflow start_date configured."
}

# Function to start Docker Compose stack
start-docker-stack() {
    echo "INFO: Fetching PostgreSQL environment variables from .env file"
    export $(grep -v '^#' .env | grep 'POSTGRES' | xargs -d '\n')

    echo "INFO: Starting Docker Compose stack"
    docker compose up -d

    echo "INFO: Adding Airflow connections for Postgres and Redis"
    docker exec -it airflow-scheduler airflow connections add opencve_postgres --conn-uri postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@postgres:5432/opencve
    docker exec -it airflow-scheduler airflow connections add opencve_redis --conn-uri redis://redis:6379 --conn-extra '{"db": 3}'

    echo "INFO: Updating OpenCVE secret key"
    export OPENCVE_SECRET_KEY=$(docker exec -it webserver python manage.py generate_secret_key)
    sed -i.bak "s/OPENCVE_SECRET_KEY=.*/OPENCVE_SECRET_KEY=$OPENCVE_SECRET_KEY/g" ../web/opencve/conf/.env && rm -f ../web/opencve/conf/.env.bak

    unset POSTGRES_USER
    unset POSTGRES_PASSWORD
    unset OPENCVE_SECRET_KEY

    echo "INFO: Restarting webserver"
    docker restart webserver

    echo "INFO: Collecting static files"
    docker exec -it webserver python manage.py collectstatic

    echo "INFO: Running Django migrations"
    docker exec -it webserver python manage.py migrate
    echo "INFO: Docker stack started successfully."
}

# Function to clone necessary repositories
clone-repositories() {
    echo "INFO: Cloning OpenCVE repositories"
    docker exec -it airflow-scheduler git clone https://github.com/opencve/opencve-kb.git /home/airflow/repositories/opencve-kb
    docker exec -it airflow-scheduler git clone https://github.com/opencve/opencve-nvd.git /home/airflow/repositories/opencve-nvd
    docker exec -it airflow-scheduler git clone https://github.com/opencve/opencve-redhat.git /home/airflow/repositories/opencve-redhat
    docker exec -it airflow-scheduler git clone https://github.com/CVEProject/cvelistV5.git /home/airflow/repositories/cvelistV5
    docker exec -it airflow-scheduler git clone https://github.com/cisagov/vulnrichment.git /home/airflow/repositories/vulnrichment
    echo "INFO: Repositories cloned successfully."
}

# Function to create a superuser for OpenCVE
create-superuser() {
    echo "INFO: Creating OpenCVE superuser"
    docker exec -it webserver python manage.py createsuperuser

    echo "INFO: Confirming new user in PostgreSQL"
    export $(grep -v '^#' .env | grep 'POSTGRES' | xargs -d '\n')
    docker exec -it postgres psql -U $POSTGRES_USER  -c 'INSERT INTO account_emailaddress(email, verified, "primary", user_id) SELECT email, 1::bool, 1::bool, id FROM opencve_users ON CONFLICT (user_id, email) DO NOTHING;'
    unset POSTGRES_USER
    unset POSTGRES_PASSWORD
    echo "INFO: Superuser created and verified."
}

# Function to import OpenCVE Knowledge Base (KB) into the database
import-opencve-kb() {
    echo "INFO: Importing OpenCVE KB, this may take 15 to 30 minutes."
    docker exec -it webserver python manage.py import_cves
    echo "INFO: OpenCVE KB imported."
}

# Function to start OpenCVE DAG in Airflow
start-opencve-dag() {
    echo "INFO: Unpausing the OpenCVE DAG in Airflow"
    docker exec -it airflow-scheduler airflow dags unpause opencve
    echo "INFO: OpenCVE DAG unpaused."
}

# Function to display usage instructions
display-usage() {
    echo "Usage: install.sh OPTIONS"
    echo ""
    echo "Examples:"
    echo "  ./install.sh"
    echo "  ./install.sh prepare"
    echo "  ./install.sh start-docker-stack"
    echo ""
    echo "OPTIONS:"
    echo ""
    echo " prepare : Add config files & set Airflow start date"
    echo " start   : Start Docker stack, clone repositories, create superuser, import KB, start OpenCVE DAG"
    echo ""
    echo "Other OPTIONS:"
    echo " add-config-files       : Add default config files"
    echo " set-airflow-start-date : Set Airflow start date"
    echo " start-docker-stack     : Start Docker Compose stack"
    echo " clone-repositories     : Clone required repositories"
    echo " create-superuser       : Create OpenCVE superuser"
    echo " import-opencve-kb      : Import OpenCVE KB"
    echo " start-opencve-dag      : Start the OpenCVE DAG in Airflow"
}

# Main logic to handle script options
_OPTIONS=$1

case $_OPTIONS in
    "help" )
        display-usage
        ;;
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
        add-config-files
        set-airflow-start-date
        start-docker-stack
        clone-repositories
        create-superuser
        import-opencve-kb
        start-opencve-dag
        ;;
esac
