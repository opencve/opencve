#!/bin/bash
#
# OpenCVE Installation Script
#
# This script initializes the environment to bootstrap the OpenCVE stack and starts it.
# It should be run as root or via sudo.
#
# Usage:
#   ./install.sh [OPTIONS] COMMANDS
#
# Options:
#   -h                Print usage statement.
#   -r <release>      Specify the release or branch to install. Default is the latest available release.
#   -f                Force overwrite of existing configuration files.
#
# Commands:
#   prepare           Prepare and add default configuration files for OpenCVE.
#   start             Start and set up the entire OpenCVE stack.
#   add-config-files  Add default configuration files.
#   init-docker-stack Initialize the Docker stack and connections.
#   clone-repositories Clone necessary repositories.
#   create-superuser  Create an OpenCVE superuser with admin privileges.
#   import-opencve-kb Import OpenCVE KB into the local database.
#   start-opencve-dag Unpause the OpenCVE DAG in Airflow.
#   docker-up         Start the OpenCVE Docker stack.
#   docker-build      Build the Docker images for the OpenCVE stack.
#   init-secret-key   Generate the OpenCVE Django secret key.
#   bye               Summarize the installation parameters.
#
# Documentation:
#   For more details, see the documentation at https://docs.opencve.io/deployment/
#
# Prerequisites:
#   Ensure that the following commands are available: docker, git, sed, grep, tr.

_GREEN="\360\237\237\242"
_YELLOW="\360\237\237\241"
_RED="\342\235\214"
_BYE="\360\237\221\213"
_DONE="\342\234\205"
_ROCKET="\360\237\232\200"

# Check for required commands
required_commands=("docker" "git" "sed" "grep" "tr")
for cmd in "${required_commands[@]}"; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: $cmd is not installed." >&2
        exit 1
    fi
done

# Function to log messages with formatting
# Usage: log "message"
# Returns: None
log() {
    local _MSG="$1"
    printf "%b\n" "$_MSG"
}

# Function to execute a command and display its status
# Usage: display-and-exec "description" [-q] command [args...]
# Returns: Exit status of the executed command
display-and-exec() {
    local _TXT="$1"
    shift
    local _QUIET=false

    if [[ "$1" == "-q" ]]; then
        _QUIET=true
        shift
    fi

    local _CMD=("$@")

    log "> $_TXT..."
    if $_QUIET; then
        "${_CMD[@]}" > /dev/null
    else
        "${_CMD[@]}"
    fi
    local _EXIT_STATUS=$?

    if [[ $_EXIT_STATUS -eq 0 ]]; then
        log "> done $_DONE"
    else
        log "> $_RED command failed: ${_CMD[*]}"
        exit $_EXIT_STATUS
    fi
}

# Function to check if a file exists and handle force option
# Usage: is-present <file_path>
# Returns: 0 if file doesn't exist or force option is used, 1 if file exists and no force option
is-present() {
    local _FILE="$1"
    if [[ -f "$_FILE" ]]; then
        log "$_YELLOW $_FILE file is already present."
        if $_FORCE; then
            log "> force option used, replacing..."
            return 0
        else
            log "Use -f option to override with the default file."
            return 1
        fi
    fi
    return 0
}

# Function to add configuration files
add-config-files() {
    local _RELEASE=$1
    local _MAJOR_VERSION=${_RELEASE:0:2}
    local _AIRFLOW_CONFIG_FILE="../scheduler/airflow.cfg"
    local _DJANGO_SETTINGS_FILE="../web/opencve/conf/settings.py"
    local _DJANGO_OPENCVE_ENV="../web/opencve/conf/.env"
    local _DOCKER_COMPOSE_ENV="./.env"
    local _NGINX_TEMPLATE="./conf/opencve.conf.template"

    log "\n--------| Find the release to install"
    if [[ $_RELEASE == "latest" ]]; then
        if [[ ! -d "../.git" ]]; then
            log "Not a git repository, we setup the release to master branch"
            _RELEASE="master"
        else
            _RELEASE=$(git describe --tags --abbrev=0)
            display-and-exec "checking out $_RELEASE" git checkout -B "$_RELEASE"
        fi
    elif [[ $_MAJOR_VERSION =~ ^[v0-1|0-1.]+$ ]]; then
        log "$_RED ERROR: this script works only for release >= 2.0.0, release given: $_RELEASE"
        exit 1
    else
        display-and-exec "checking out $_RELEASE" git checkout -B "$_RELEASE"
    fi

    log "\n--------| Airflow configuration"
    is-present "$_AIRFLOW_CONFIG_FILE"
    if [[ $? == 0 ]]; then
        display-and-exec "copying airflow config file" cp "$_AIRFLOW_CONFIG_FILE.example" "$_AIRFLOW_CONFIG_FILE"
        local _START_DATE
        _START_DATE=$(date '+%Y-%m-%d')
        display-and-exec "updating start date for Airflow dag" sed -i.bak "s/start_date = .*/start_date = $_START_DATE/g" "$_AIRFLOW_CONFIG_FILE" && rm -f "$_AIRFLOW_CONFIG_FILE.bak"
        local _CONFIGURED_START_DATE
        _CONFIGURED_START_DATE=$(grep 'start_date' "$_AIRFLOW_CONFIG_FILE")
        log "Default configuration: $_CONFIGURED_START_DATE"
    fi

    log "\n--------| Django settings and .env file"
    is-present "$_DJANGO_SETTINGS_FILE"
    if [[ $? == 0 ]]; then
        display-and-exec "copying Django settings" cp "$_DJANGO_SETTINGS_FILE.example" "$_DJANGO_SETTINGS_FILE"
    fi
    is-present "$_DJANGO_OPENCVE_ENV"
    if [[ $? == 0 ]]; then
        display-and-exec "copying Webserver env file" cp "$_DJANGO_OPENCVE_ENV.example" "$_DJANGO_OPENCVE_ENV"
    fi

    log "\n--------| Docker compose .env file"
    is-present "$_DOCKER_COMPOSE_ENV"
    if [[ $? == 0 ]]; then
        display-and-exec "copying Docker compose env file" cp "./conf/$_DOCKER_COMPOSE_ENV.example" "$_DOCKER_COMPOSE_ENV"
    fi

    display-and-exec "updating OpenCVE release to $_RELEASE" sed -i.bak "s,OPENCVE_VERSION=.*,OPENCVE_VERSION=$_RELEASE,g" "$_DOCKER_COMPOSE_ENV" && rm -f "$_DOCKER_COMPOSE_ENV.bak"

    log "\n--------| Nginx OpenCVE template"
    is-present "$_NGINX_TEMPLATE"
    if [[ $? == 0 ]]; then
        display-and-exec "copying OpenCVE configuration" cp "$_NGINX_TEMPLATE.example" "$_NGINX_TEMPLATE"
        display-and-exec "copying empty default configuration" cp ./conf/default.conf.template.example ./conf/default.conf.template
    fi

    log "\n\n$_GREEN The configuration files are all set, you can update them now if you want before starting the entire docker stack:"
    log " Nginx: $_NGINX_TEMPLATE"
    log " Airflow: $_AIRFLOW_CONFIG_FILE"
    log " Webserver: $_DJANGO_OPENCVE_ENV & $_DJANGO_SETTINGS_FILE"
    log " Docker compose: $_DOCKER_COMPOSE_ENV"
    log "\nSee the documentation for details: https://docs.opencve.io/deployment/#configuration"
    log "\n $_ROCKET You can now run: ./install.sh start"
}

# Function to build Docker images
docker-build() {
    log "\n--------| Docker compose build"
    display-and-exec "building OpenCVE docker images" docker compose build --no-cache
}

# Function to start Docker containers
docker-up() {
    log "\n--------| Docker compose up"
    display-and-exec "starting OpenCVE docker stack" docker compose up -d

    log "\n--------| Collect static files from Django webserver"
    display-and-exec "collecting latest static files" -q docker exec webserver python manage.py collectstatic --no-input

    log "\n--------| Apply Django webserver DB migration"
    display-and-exec "migrating DB schema with latest changes" -q docker exec webserver python manage.py migrate
}

# Function to set Airflow connections
set-airflow-connections() {
    export $(grep -v '^#' .env | grep -E '^POSTGRES' | tr '\n' ' ')

    log "\n--------| Add Airflow connections"
    display-and-exec "adding Postgresql Airflow connection" -q docker exec airflow-scheduler airflow connections add opencve_postgres --conn-uri "postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@postgres:5432/opencve"
    display-and-exec "adding Redis Airflow connection" -q docker exec airflow-scheduler airflow connections add opencve_redis --conn-uri "redis://redis:6379" --conn-extra '{"db": 3}'

    unset POSTGRES_USER
    unset POSTGRES_PASSWORD
}

# Function to initialize the secret key
init-secret-key() {
    log "\n--------| Generate OpenCVE secret key"

    export _OPENCVE_SECRET_KEY=$(docker exec webserver python manage.py generate_secret_key | sed -e 's/[&!$]//g')

    display-and-exec "cleaning old OpenCVE secret key" sed -i.bak "s/^OPENCVE_SECRET_KEY=.*/OPENCVE_SECRET_KEY=/g" ../web/opencve/conf/.env
    display-and-exec "updating with new OpenCVE secret key" sed -i.bak "s,^OPENCVE_SECRET_KEY=.*,OPENCVE_SECRET_KEY='$_OPENCVE_SECRET_KEY',g" ../web/opencve/conf/.env && rm -f ../web/opencve/conf/.env.bak

    unset _OPENCVE_SECRET_KEY
}

# Function to initialize the Docker stack
init-docker-stack() {
    docker-up
    set-airflow-connections
    init-secret-key

    log "\n--------| Webserver restart"
    display-and-exec "restarting webserver docker instance" -q docker restart webserver
}

# Function to clone necessary repositories
clone-repositories() {
    log "\n--------| Initialize OpenCVE repositories"
    display-and-exec "cloning opencve-kb" docker exec airflow-scheduler git clone https://github.com/opencve/opencve-kb.git /home/airflow/repositories/opencve-kb
    display-and-exec "cloning opencve-nvd" docker exec airflow-scheduler git clone https://github.com/opencve/opencve-nvd.git /home/airflow/repositories/opencve-nvd
    display-and-exec "cloning opencve-redhat" docker exec airflow-scheduler git clone https://github.com/opencve/opencve-redhat.git /home/airflow/repositories/opencve-redhat
    display-and-exec "cloning cvelistV5" docker exec airflow-scheduler git clone https://github.com/CVEProject/cvelistV5.git /home/airflow/repositories/cvelistV5
    display-and-exec "cloning vulnrichment" docker exec airflow-scheduler git clone https://github.com/cisagov/vulnrichment.git /home/airflow/repositories/vulnrichment
}

# Function to import OpenCVE KB
import-opencve-kb() {
    log "\n--------| Import OpenCVE KB inside the database, it can take 10 to 30 min"
    display-and-exec "importing CVEs" docker exec webserver python manage.py import_cves
}

# Function to start the OpenCVE DAG
start-opencve-dag() {
    log "\n--------| Unpause Airflow OpenCVE dag to start to update local repositories and alerts"
    display-and-exec "unpausing OpenCVE Airflow dag" -q docker exec airflow-scheduler airflow dags unpause opencve
}

# Function to create a superuser
create-superuser() {
    log "\n--------| Create OpenCVE admin user"
    display-and-exec "creating OpenCVE admin user" docker exec -it webserver python manage.py createsuperuser

    export $(grep -v '^#' .env | grep -E '^POSTGRES' | tr '\n' ' ')

    log "\n--------| Auto confirm the created user"
    display-and-exec "confirming the created admin user" -q docker exec postgres psql -U "$POSTGRES_USER" -c "INSERT INTO account_emailaddress(email, verified, \"primary\", user_id) SELECT email, 1::bool, 1::bool, id FROM opencve_users ON CONFLICT (user_id, email) DO NOTHING;"

    unset POSTGRES_USER
    unset POSTGRES_PASSWORD
}

# Function to summarize the installation parameters
install-end() {
    export $(grep -v '^#' .env | grep -E '^OPENCVE_' | tr '\n' ' ')
    export $(grep -v '^#' .env | grep -E '^_AIRFLOW_WWW_USER_' | tr '\n' ' ')
    export $(grep -v '^#' .env | grep -E '^AIRFLOW_WEBSERVER_PORT' | tr '\n' ' ')

    local _OPENCVE_PORT="${OPENCVE_PORT:-80}"
    local _OPENCVE_VERSION="${OPENCVE_VERSION:-unknown}"
    local _AIRFLOW_PORT="${AIRFLOW_WEBSERVER_PORT:-8080}"
    local _AIRFLOW_USER="${_AIRFLOW_WWW_USER_USERNAME:-airflow}"
    local _AIRFLOW_PASS="${_AIRFLOW_WWW_USER_PASSWORD:-airflow}"

    log "\n\n$_GREEN Everything is set up, you can now access to OpenCVE locally:"
    log "- on port $_OPENCVE_PORT for OpenCVE web instance"
    log " You can login with your account and password set at the previous step 'Create OpenCVE admin user'."
    log " You can set a new one with the following command: ./install.sh create-superuser"
    log " The installed version is: $_OPENCVE_VERSION"
    log "- on port $_AIRFLOW_PORT for OpenCVE Airflow scheduler"
    log " You can login with the username \"$_AIRFLOW_USER\" and password \"$_AIRFLOW_PASS\"."

    log "\n $_BYE Installation complete! Thank you for choosing OpenCVE!"

    unset _AIRFLOW_WWW_USER_USERNAME
    unset _AIRFLOW_WWW_USER_PASSWORD
}

# Function to display usage information
display-usage() {
    local _S1=7
    local _S2=9
    local _BOLD="\033[1m"
    local _NC="\033[0m"

    log "\n${_BOLD}USAGE${_NC}"
    log "%${_S1}s./install.sh [OPTIONS] COMMANDS"

    log "\n${_BOLD}OPTIONS${_NC}"
    log "%${_S1}s-h"
    log "%${_S2}sPrint usage statement."
    log "%${_S1}s-r"
    log "%${_S2}sRelease or branch to install."
    log "%${_S2}sDefault: use the latest available release in the local OpenCVE repository."

    log "${_BOLD}COMMANDS${_NC}"
    log "%${_S1}sprepare"
    log "%${_S2}sIt prepares and adds the default configuration files for OpenCVE. If no OPTION is given, it sets the value for the latest available release."
    log "%${_S2}sThis is executed if no COMMAND is given. It overrides previous setting files if any."
    log "%${_S1}sstart"
    log "%${_S2}sStart and setup the entire OpenCVE stack. It needs to be done after the prepare command."

    log "${_BOLD}SPECIFIC COMMANDS${_NC}"
    log "%${_S1}sadd-config-files"
    log "%${_S2}sAdd default configurations files."
    log "%${_S1}sinit-docker-stack"
    log "%${_S2}sPerform docker compose up for OpenCVE stack from its docker-compose.yaml and initialize connections."
    log "%${_S1}sclone-repositories"
    log "%${_S2}sClone KB repositories. It needs to be done one time, if you need to retry it, you need to delete the associated docker volume."
    log "%${_S1}screate-superuser"
    log "%${_S2}sCreate an OpenCVE super user with admin privileges."
    log "%${_S1}simport-opencve-kb"
    log "%${_S2}sImport OpenCVE KB inside local database. It needs to be done only one time."
    log "%${_S1}sstart-opencve-dag"
    log "%${_S2}sUnpause OpenCVE Dag in Airflow to start to update local repositories and send alerts."
    log "%${_S1}sstart-docker"
    log "%${_S2}sPerform docker compose up with OpenCVE stack from its docker-compose.yaml."
    log "%${_S1}sbuild-docker"
    log "%${_S2}sBuild the docker images for OpenCVE stack from its docker-compose.yaml."
    log "%${_S1}sinit-secret-key"
    log "%${_S2}sGenerate OpenCVE Django secret key."

    log "${_BOLD}EXAMPLES${_NC}"
    log "%${_S1}s./install.sh"
    log "%${_S2}sEquivalent to ./install.sh prepare."
    log "%${_S1}s./install.sh start"
    log "%${_S2}sIt starts and sets everything up to have a working OpenCVE stack."
    log "%${_S1}s./install.sh -r master"
    log "%${_S2}sIt sets the configuration files to install the master branch of OpenCVE. It needs to be done before the start command."

    log "${_BOLD}DOCUMENTATION${_NC}"
    log "%${_S1}shttps://docs.opencve.io/deployment/"
}

_RELEASE="latest"
_FORCE=false
OPTSTRING=":r:fh"
while getopts ${OPTSTRING} opt; do
    case ${opt} in
        f)
            _FORCE=true
            ;;
        h)
            display-usage
            exit 1
            ;;
        r)
            _RELEASE="${OPTARG}"
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

shift $((OPTIND - 1))

_COMMAND=$1
case $_COMMAND in
    "prepare" )
        add-config-files "$_RELEASE"
        ;;
    "start" )
        init-docker-stack
        clone-repositories
        import-opencve-kb
        start-opencve-dag
        create-superuser
        install-end
        ;;
    "add-config-files" )
        add-config-files
        ;;
    "init-docker-stack" )
        init-docker-stack
        ;;
    "clone-repositories" )
        clone-repositories
        ;;
    "import-opencve-kb" )
        import-opencve-kb
        ;;
    "start-opencve-dag" )
        start-opencve-dag
        ;;
    "create-superuser" )
        create-superuser
        ;;
    "docker-up" )
        docker-up
        ;;
    "docker-build" )
        docker-build
        ;;
    "init-secret-key" )
        init-secret-key
        ;;
    "bye" )
        install-end
        ;;
    "" )
        add-config-files "$_RELEASE"
        ;;
    * )
        display-usage
        ;;
esac
