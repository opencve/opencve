#!/bin/bash
#
# This script initializes the environment to bootstrap OpenCVE stack and starts it
# Run is as root or via sudo

display-and-exec() {
     _TXT="$1"
     _CMD="$2"

    printf "> %s...\n" "$_TXT"
    eval $_CMD
    _EXIT_STATUS=$?

    if [[ $_EXIT_STATUS -eq 0 ]]; then
    printf "> done %b\n" "\U2705"
    else
        printf "> %b %s\n" "\U274C" "command failed: $_CMD"
        exit $_EXIT_STATUS
    fi

}

add-config-files() {

    _RELEASE=$1
    _MAJOR_VERSION=${_RELEASE:0:2}

    printf "\n--------| %s\n" "Check the release to install"
    if [[ $_RELEASE == "latest" ]] ; then
        if [ ! -d "../.git" ]; then
            printf "%s\n" "Not a git repository, we setup the release to master branch"
            _RELEASE="master"
        else
            _RELEASE=`git describe --tags --abbrev=0`
            display-and-exec "checking out $_RELEASE" "git checkout -B $_RELEASE"
        fi
    elif [[ $_MAJOR_VERSION =~ ^[v0-1|0-1.]+$ ]] ; then
        printf "%s\n" "ERROR: this script works only for release >= 2.0.0, release given: $_RELEASE"
        exit 1
    else
        display-and-exec "checking out $_RELEASE" "git checkout -B $_RELEASE"
    fi

    printf "\n--------| %s\n" "Airflow configuration"
    display-and-exec "copying airflow config file" "cp ../scheduler/airflow.cfg.example ../scheduler/airflow.cfg"
    _START_DATE=$(date '+%Y-%m-%d')
    display-and-exec "updating start date for Airflow dag" "sed -i.bak 's/start_date = .*/start_date = $_START_DATE/g' ../scheduler/airflow.cfg && rm -f ../scheduler/airflow.cfg.bak"
    _CONFIGURED_START_DATE=$(grep 'start_date' ../scheduler/airflow.cfg)
    printf "%s\n" "Default configuration: $_CONFIGURED_START_DATE"

    printf "\n--------| %s\n" "Django settings and .env file"
    display-and-exec "copying Django settings" "cp ../web/opencve/conf/settings.py.example ../web/opencve/conf/settings.py"
    display-and-exec "copying Webserver env file" "cp ../web/opencve/conf/.env.example ../web/opencve/conf/.env"

    printf "\n--------| %s\n" "Docker compose .env file"
    display-and-exec "copying Docker compose env file" "cp ./conf/.env.example ./.env"
    display-and-exec "updating OpenCVE release to $_RELEASE" "sed -i.bak 's,OPENCVE_VERSION=.*,OPENCVE_VERSION=$_RELEASE,g' ./.env && rm -f ./.env.bak"

    printf "\n--------| %s\n" "Nginx OpenCVE template"
    display-and-exec "copying OpenCVE configuration" "cp ./conf/opencve.conf.template.example ./conf/opencve.conf.template"
    display-and-exec "copying empty default configuration" "cp ./conf/default.conf.template.example ./conf/default.conf.template"

    printf "\n\n%b\n" "\U1F7E2 The default configuration files are all set, you can update them now if you want before starting the entire docker stack:"
    printf "%-15s %s\n" " Docker compose" ": ./.env"
    printf "%-15s %s\n" " Webserver" ": ../web/opencve/conf/.env"
    printf "%-15s %s\n" " Airflow" ": ../scheduler/airflow.cfg"
    printf "%-15s %s\n" " Django" ": ../web/opencve/conf/settings.py"
    printf "\n%s\n" "See the documentation for details: https://docs.opencve.io/deployment/#configuration"
    printf "\n%b\n\n" " \U1F680 You can now run: ./install.sh start"

}

start-docker-stack() {

    export $(grep -v '^#' .env | grep -E '^POSTGRES' | tr '\n' ' ')

    printf "\n--------| %s\n" "Docker compose"
    display-and-exec "starting OpenCVE docker stack" "docker compose up -d"

    printf "\n--------| %s\n" "Airflow connections"
    display-and-exec "adding Postgresql Airflow connection" "docker exec airflow-scheduler airflow connections add opencve_postgres --conn-uri postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@postgres:5432/opencve > /dev/null"
    display-and-exec "adding Redis Airflow connection" "docker exec airflow-scheduler airflow connections add opencve_redis --conn-uri redis://redis:6379 --conn-extra '{\"db\": 3}' > /dev/null"

    printf "\n--------| %s\n" "OpenCVE secret key"
    _OPENCVE_SECRET_KEY=$(docker exec webserver python manage.py generate_secret_key)
    display-and-exec "cleaning old OpenCVE secret key" "sed -i.bak 's/OPENCVE_SECRET_KEY=.*/OPENCVE_SECRET_KEY=/g' ../web/opencve/conf/.env"
    display-and-exec "updating with new OpenCVE secret key" "sed -i.bak \"s,OPENCVE_SECRET_KEY=.*,OPENCVE_SECRET_KEY=\'$_OPENCVE_SECRET_KEY\',g\" ../web/opencve/conf/.env && rm -f ../web/opencve/conf/.env.bak"

    unset POSTGRES_USER
    unset POSTGRES_PASSWORD
    unset _OPENCVE_SECRET_KEY

    printf "\n--------| %s\n" "Webserver restart"
    display-and-exec "restarting webserver docker instance" "docker restart webserver > /dev/null"

    printf "\n--------| %s\n" "Collect static files from Django webserver"
    display-and-exec "collecting latest static files" "docker exec webserver python manage.py collectstatic > /dev/null"

    printf "\n--------| %s\n" "Apply Django webserver DB migration"
    display-and-exec "migrating DB schema with latest changes" "docker exec webserver python manage.py migrate > /dev/null"

}

clone-repositories() {

    printf "\n--------| %s\n" "Setup OpenCVE repositories"
    display-and-exec "cloning opencve-kb" "docker exec airflow-scheduler git clone https://github.com/opencve/opencve-kb.git /home/airflow/repositories/opencve-kb"
    display-and-exec "cloning opencve-nvd" "docker exec airflow-scheduler git clone https://github.com/opencve/opencve-nvd.git /home/airflow/repositories/opencve-nvd"
    display-and-exec "cloning opencve-redhat" "docker exec airflow-scheduler git clone https://github.com/opencve/opencve-redhat.git /home/airflow/repositories/opencve-redhat"
    display-and-exec "cloning cvelistV5" "docker exec airflow-scheduler git clone https://github.com/CVEProject/cvelistV5.git /home/airflow/repositories/cvelistV5"
    display-and-exec "cloning vulnrichment" "docker exec airflow-scheduler git clone https://github.com/cisagov/vulnrichment.git /home/airflow/repositories/vulnrichment"

}

create-superuser() {

    export $(grep -v '^#' .env | grep -E '^POSTGRES' | tr '\n' ' ')

    printf "\n--------| %s\n" "Create admin user on OpenCVE"
    display-and-exec "creating OpenCVE admin user" "docker exec -it webserver python manage.py createsuperuser"

    printf "\n--------| %s\n" "Auto confirm the created user"
    display-and-exec "confirming the created admin user" "docker exec postgres psql -U $POSTGRES_USER  -c 'INSERT INTO account_emailaddress(email, verified, \"primary\", user_id) SELECT email, 1::bool, 1::bool, id FROM opencve_users ON CONFLICT (user_id, email) DO NOTHING;' > /dev/null"

    unset POSTGRES_USER
    unset POSTGRES_PASSWORD

}

import-opencve-kb() {

    printf "\n--------| %s\n" "Import OpenCVE KB inside the database, this can take 15 to 30min."
    display-and-exec "importing CVEs" "docker exec webserver python manage.py import_cves"

}

start-opencve-dag() {

    printf "\n--------| %s\n" "Unpause Airflow OpenCVE dag to start to update local repositories and alerts"
    display-and-exec "unpausing OpenCVE Airflow dag" "docker exec airflow-scheduler airflow dags unpause opencve > /dev/null"

}

install-end() {

    printf "\n\n\n%b" "\U1F7E2 Everything is set up, you can now access to OpenCVE locally:"
    printf "\n%s" "- on port 80 for OpenCVE web instance"
    printf "\n%s" "- on port 8080 for OpenCVE Airflow scheduler"
    printf "\n\n%b\n\n" "\U1F44B Thank you for trying out OpenCVE!"

}

display-usage() {
    _S1=7
    _S2=9
    _BOLD="\033[1m"
    _NC="\033[0m"

    printf "\n${_BOLD}%s${_NC}\n" "USAGE"
    printf "%${_S1}s%s\n" "" "./install.sh [OPTIONS] COMMANDS"

    printf "\n${_BOLD}%s${_NC}\n" "OPTIONS"
    printf "%${_S1}s%s\n" "" "-h"
    printf "%${_S2}s%s\n\n" "" "Print usage statement."
    printf "%${_S1}s%s\n" "" "-r"
    printf "%${_S2}s%s\n" "" "Release or branch to install."
    printf "%${_S2}s%s\n\n" "" "Default: latest available release."

    printf "${_BOLD}%s${_NC}\n" "COMMANDS"
    printf "%${_S1}s%s\n" "" "prepare"
    printf "%${_S2}s%s\n" "" "It prepares and adds the default configuration files for OpenCVE. If no OPTION is given, it sets the value for the latest available release."
    printf "%${_S2}s%s\n\n" "" "This is executed if no COMMAND is given."
    printf "%${_S1}s%s\n" "" "start"
    printf "%${_S2}s%s\n\n" "" "Start and setup the entire OpenCVE stack. It needs to be done after the prepare command."

    printf "${_BOLD}%s${_NC}\n" "SPECIFIC COMMANDS"
    printf "%${_S1}s%s\n" "" "add-config-files"
    printf "%${_S2}s%s\n\n" "" "Add default configurations files."
    printf "%${_S1}s%s\n" "" "start-docker-stack"
    printf "%${_S2}s%s\n\n" "" "Start docker compose OpenCVE stack from docker-compose.yaml."
    printf "%${_S1}s%s\n" "" "clone-repositories"
    printf "%${_S2}s%s\n\n" "" "Clone KB repositories. It needs to be done one time, if you need to retry it, you need to delete the associated docker volume."
    printf "%${_S1}s%s\n" "" "create-superuser"
    printf "%${_S2}s%s\n\n" "" "Create an OpenCVE super user with admin privileges."
    printf "%${_S1}s%s\n" "" "import-opencve-kb"
    printf "%${_S2}s%s\n\n" "" "Import OpenCVE KB inside local database. It needs to be done only one time."
    printf "%${_S1}s%s\n" "" "start-opencve-dag"
    printf "%${_S2}s%s\n\n" "" "Unpause OpenCVE Dag in Airflow to start to update local repositories and send alerts."

    printf "${_BOLD}%s${_NC}\n" "EXAMPLES"
    printf "%${_S1}s%s\n" "" "./install.sh"
    printf "%${_S2}s%s\n\n" "" "Equivalent to ./install.sh prepare."
    printf "%${_S1}s%s\n" "" "./install.sh start"
    printf "%${_S2}s%s\n\n" "" "It starts the entire OpenCVE stack."
    printf "%${_S1}s%s\n" "" "./install.sh -r master"
    printf "%${_S2}s%s\n\n" "" "It sets the configuration files to install the master branch of OpenCVE. It needs to be done before the start command."

    printf "${_BOLD}%s${_NC}\n" "DOCUMENTATION"
    printf "%${_S1}s%s\n\n" "" "https://docs.opencve.io/deployment/"

}

_RELEASE="latest"
OPTSTRING=":r:h"

while getopts ${OPTSTRING} opt; do
  case ${opt} in
    r)
      _RELEASE="${OPTARG}"
      ;;
    h)
      display-usage
      exit 1
      ;;
    :)
      echo "Option -${OPTARG} requires an argument."
      exit 1
      ;;
    ?)
      echo "Invalid argument: -${OPTARG}."
      exit 1
      ;;
  esac
done

_COMMAND=$1

case $_COMMAND in
    "prepare" )
        add-config-files $_RELEASE
        ;;
    "start" )
        start-docker-stack
        clone-repositories
        create-superuser
        import-opencve-kb
        start-opencve-dag
        install-end
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
    "" )
        add-config-files $_RELEASE
        ;;
    * )
        display-usage
        ;;
esac
