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
#   -r <release>      Specify the release or branch to install. Default is master.
#   -f                Force overwrite of existing configuration files.
#   -y                Skip confirmation prompts (reset command).
#
# Commands:
#   prepare           Prepare and add default configuration files for OpenCVE.
#   start             Start and set up the entire OpenCVE stack.
#   upgrade           Upgrade an existing installation (pull, rebuild, migrate).
#   reset             Stop stack, remove Docker volumes and install state.
#   add-config-files  Add default configuration files.
#   init-docker-stack Initialize the Docker stack and connections.
#   clone-repositories Clone necessary repositories.
#   create-superuser  Create an OpenCVE superuser with admin privileges.
#   import-opencve-kb Import OpenCVE KB into the local database.
#   start-opencve-dag Unpause all OpenCVE DAGs in Airflow.
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

_INSTALL_STATE_FILE="./.install-state"
_AIRFLOW_DAGS=(opencve summarize_reports sync_weaknesses clean_reports check_smtp)

# Check for required commands
required_commands=("docker" "git" "sed" "grep" "tr")
for cmd in "${required_commands[@]}"; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: $cmd is not installed." >&2
        exit 1
    fi
done

# Function to log messages with formatting
log() {
    local _MSG="$1"
    printf "%b\n" "$_MSG"
}

# Function to execute a command and display its status
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

# Read a value from the install state file.
install-state-get() {
    grep -E "^${1}=" "$_INSTALL_STATE_FILE" 2>/dev/null | cut -d= -f2-
}

# Write or update a value in the install state file.
install-state-set() {
    local _KEY="$1"
    local _VAL="$2"
    touch "$_INSTALL_STATE_FILE"
    if grep -qE "^${_KEY}=" "$_INSTALL_STATE_FILE"; then
        sed -i.bak "s|^${_KEY}=.*|${_KEY}=${_VAL}|" "$_INSTALL_STATE_FILE" && rm -f "${_INSTALL_STATE_FILE}.bak"
    else
        echo "${_KEY}=${_VAL}" >> "$_INSTALL_STATE_FILE"
    fi
}

# Return whether an install state flag is set to true.
install-state-is() {
    [[ "$(install-state-get "$1")" == "true" ]]
}

# Normalize release aliases (latest becomes master).
normalize-release() {
    local _RELEASE="$1"
    if [[ "$_RELEASE" == "latest" ]]; then
        _RELEASE="master"
    fi
    printf "%s" "$_RELEASE"
}

# Ensure docker/.env exists before running stack commands.
ensure-env-file() {
    if [[ ! -f "./.env" ]]; then
        log "$_RED ERROR: docker/.env not found. Run ./install.sh prepare first."
        exit 1
    fi
}

# Ensure the OpenCVE repository is a git clone (required for upgrade).
ensure-git-repo() {
    if [[ ! -d "../.git" ]]; then
        log "$_RED ERROR: No git repository detected."
        log "Upgrade requires a git clone. For tarball installs use: ./install.sh -r <version> prepare && ./install.sh start"
        exit 1
    fi
}

# Return the current local git branch, tag, or commit reference.
get-local-git-ref() {
    local _REF
    _REF=$(git -C .. rev-parse --abbrev-ref HEAD 2>/dev/null || true)
    if [[ "$_REF" == "HEAD" ]]; then
        _REF=$(git -C .. describe --tags --exact-match 2>/dev/null || git -C .. rev-parse --short HEAD)
    fi
    printf "%s" "$_REF"
}

# Abort if OPENCVE_VERSION in .env does not match the local git checkout.
ensure-version-consistency() {
    ensure-env-file
    export $(grep -v '^#' .env | grep -E '^OPENCVE_VERSION=' | tr '\n' ' ')
    local _ENV_VERSION="${OPENCVE_VERSION:-}"
    unset OPENCVE_VERSION

    if [[ ! -d "../.git" ]]; then
        return 0
    fi

    local _GIT_REF
    _GIT_REF=$(get-local-git-ref)
    if [[ "$_ENV_VERSION" != "$_GIT_REF" ]]; then
        log "$_RED ERROR: OPENCVE_VERSION in .env ($_ENV_VERSION) does not match local git checkout ($_GIT_REF)."
        log "Run: ./install.sh -r $_ENV_VERSION prepare"
        exit 1
    fi
}

# Verify webserver and scheduler containers match OPENCVE_VERSION from .env.
verify-container-versions() {
    ensure-env-file
    export $(grep -v '^#' .env | grep -E '^OPENCVE_VERSION=' | tr '\n' ' ')
    local _EXPECTED="${OPENCVE_VERSION:-}"
    unset OPENCVE_VERSION

    local _WEB_VERSION _SCHED_VERSION
    _WEB_VERSION=$(docker compose exec -T webserver printenv OPENCVE_VERSION 2>/dev/null || true)
    _SCHED_VERSION=$(docker compose exec -T airflow-scheduler printenv OPENCVE_VERSION 2>/dev/null || true)

    if [[ "$_WEB_VERSION" != "$_EXPECTED" ]] || [[ "$_SCHED_VERSION" != "$_EXPECTED" ]]; then
        log "$_RED ERROR: Container version mismatch."
        log "  Expected: $_EXPECTED"
        log "  Webserver: ${_WEB_VERSION:-unknown}"
        log "  Scheduler: ${_SCHED_VERSION:-unknown}"
        exit 1
    fi
    log "> Container versions match OPENCVE_VERSION=$_EXPECTED $_DONE"
}

# Update OPENCVE_VERSION in docker/.env and the install state file.
update-opencve-version-in-env() {
    local _RELEASE="$1"
    _RELEASE=$(normalize-release "$_RELEASE")
    ensure-env-file
    display-and-exec "updating OpenCVE release to $_RELEASE" sed -i.bak "s,OPENCVE_VERSION=.*,OPENCVE_VERSION=$_RELEASE,g" "./.env" && rm -f "./.env.bak"
    install-state-set OPENCVE_VERSION "$_RELEASE"
}

# Checkout the requested release in the local git repository.
checkout-release() {
    local _RELEASE="$1"
    _RELEASE=$(normalize-release "$_RELEASE")
    if [[ -d "../.git" ]]; then
        display-and-exec "checking out $_RELEASE" git -C .. checkout -B "$_RELEASE"
    fi
}

# Fetch and pull the requested release from the remote git repository.
pull-release() {
    local _RELEASE="$1"
    _RELEASE=$(normalize-release "$_RELEASE")
    ensure-git-repo
    display-and-exec "fetching git updates" git -C .. fetch --all --tags
    if [[ "$_RELEASE" == "master" ]]; then
        display-and-exec "pulling master branch" git -C .. checkout master
        display-and-exec "updating master branch" git -C .. pull --ff-only origin master
    else
        display-and-exec "checking out $_RELEASE" git -C .. checkout "$_RELEASE"
        if git -C .. rev-parse --verify "origin/${_RELEASE}" &>/dev/null; then
            display-and-exec "pulling $_RELEASE branch" git -C .. pull --ff-only origin "$_RELEASE"
        fi
    fi
}

# Pause all OpenCVE Airflow DAGs.
pause-all-dags() {
    log "\n--------| Pause Airflow DAGs"
    local _DAG
    for _DAG in "${_AIRFLOW_DAGS[@]}"; do
        docker compose exec airflow-scheduler airflow dags pause "$_DAG" > /dev/null 2>&1 || true
    done
    log "> all DAGs paused $_DONE"
}

# Unpause all OpenCVE Airflow DAGs.
unpause-all-dags() {
    log "\n--------| Unpause Airflow DAGs"
    local _DAG
    for _DAG in "${_AIRFLOW_DAGS[@]}"; do
        display-and-exec "unpausing $_DAG dag" -q docker compose exec airflow-scheduler airflow dags unpause "$_DAG"
    done
}

# Wait for running Airflow DAG tasks to finish before upgrading.
wait-for-running-dag-runs() {
    local _TIMEOUT=600
    local _ELAPSED=0
    log "\n--------| Wait for running DAG tasks to finish"
    while [[ $_ELAPSED -lt $_TIMEOUT ]]; do
        local _RUNNING
        _RUNNING=$(docker compose exec -T airflow-scheduler airflow dags list-runs -s running 2>/dev/null | grep -c running || true)
        if [[ "$_RUNNING" -eq 0 ]]; then
            log "> no running DAG tasks $_DONE"
            return 0
        fi
        sleep 10
        _ELAPSED=$((_ELAPSED + 10))
    done
    log "$_YELLOW Warning: timed out waiting for running DAG tasks. Continuing upgrade."
}

# Function to add configuration files
add-config-files() {
    local _RELEASE
    _RELEASE=$(normalize-release "$1")
    local _MAJOR_VERSION=${_RELEASE:0:2}
    local _AIRFLOW_CONFIG_FILE="../scheduler/airflow.cfg"
    local _DJANGO_SETTINGS_FILE="../web/opencve/conf/settings.py"
    local _DJANGO_OPENCVE_ENV="../web/opencve/conf/.env"
    local _DOCKER_COMPOSE_ENV="./.env"
    local _NGINX_TEMPLATE="./conf/opencve.conf.template"
    local _CONFIG_BLOCKED=false

    log "\n--------| Find the release to install"
    if [[ $_MAJOR_VERSION =~ ^[v0-1|0-1.]+$ ]]; then
        log "$_RED ERROR: this script works only for release >= 2.0.0, release given: $_RELEASE"
        exit 1
    fi
    checkout-release "$_RELEASE"

    log "\n--------| Airflow configuration"
    is-present "$_AIRFLOW_CONFIG_FILE"
    if [[ $? == 0 ]]; then
        display-and-exec "copying airflow config file" cp "$_AIRFLOW_CONFIG_FILE.example" "$_AIRFLOW_CONFIG_FILE"
        local _START_DATE
        _START_DATE=$(date '+%Y-%m-%d')
        display-and-exec "updating start date for opencve dag" sed -i.bak "s/start_date = .*/start_date = $_START_DATE/g" "$_AIRFLOW_CONFIG_FILE" && rm -f "$_AIRFLOW_CONFIG_FILE.bak"
        display-and-exec "updating start date for summarize_reports dag" sed -i.bak "s/start_date_summarize_reports = .*/start_date_summarize_reports = $_START_DATE/g" "$_AIRFLOW_CONFIG_FILE" && rm -f "$_AIRFLOW_CONFIG_FILE.bak"
        display-and-exec "updating start date for sync_weaknesses dag" sed -i.bak "s/start_date_sync_weaknesses = .*/start_date_sync_weaknesses = $_START_DATE/g" "$_AIRFLOW_CONFIG_FILE" && rm -f "$_AIRFLOW_CONFIG_FILE.bak"
        local _CONFIGURED_START_DATE
        _CONFIGURED_START_DATE=$(grep 'start_date' "$_AIRFLOW_CONFIG_FILE")
        log "Default configuration: $_CONFIGURED_START_DATE"
    else
        _CONFIG_BLOCKED=true
    fi

    log "\n--------| Django settings and .env file"
    is-present "$_DJANGO_SETTINGS_FILE"
    if [[ $? == 0 ]]; then
        display-and-exec "copying Django settings" cp "$_DJANGO_SETTINGS_FILE.example" "$_DJANGO_SETTINGS_FILE"
    else
        _CONFIG_BLOCKED=true
    fi
    is-present "$_DJANGO_OPENCVE_ENV"
    if [[ $? == 0 ]]; then
        display-and-exec "copying Webserver env file" cp "$_DJANGO_OPENCVE_ENV.example" "$_DJANGO_OPENCVE_ENV"
    else
        _CONFIG_BLOCKED=true
    fi

    log "\n--------| Docker compose .env file"
    is-present "$_DOCKER_COMPOSE_ENV"
    if [[ $? == 0 ]]; then
        display-and-exec "copying Docker compose env file" cp "./conf/$_DOCKER_COMPOSE_ENV.example" "$_DOCKER_COMPOSE_ENV"
    else
        _CONFIG_BLOCKED=true
    fi

    update-opencve-version-in-env "$_RELEASE"

    log "\n--------| Nginx OpenCVE template"
    is-present "$_NGINX_TEMPLATE"
    if [[ $? == 0 ]]; then
        display-and-exec "copying OpenCVE configuration" cp "$_NGINX_TEMPLATE.example" "$_NGINX_TEMPLATE"
        display-and-exec "copying empty default configuration" cp ./conf/default.conf.template.example ./conf/default.conf.template
    else
        _CONFIG_BLOCKED=true
    fi

    log "\n\n$_GREEN The configuration files are all set, you can update them now if you want before starting the entire docker stack:"
    log " Nginx: $_NGINX_TEMPLATE"
    log " Airflow: $_AIRFLOW_CONFIG_FILE"
    log " Webserver: $_DJANGO_OPENCVE_ENV & $_DJANGO_SETTINGS_FILE"
    log " Docker compose: $_DOCKER_COMPOSE_ENV"
    log "\nSee the documentation for details: https://docs.opencve.io/deployment/#configuration"
    if $_CONFIG_BLOCKED; then
        log "\n $_YELLOW Some config files already exist. OPENCVE_VERSION was updated in $_DOCKER_COMPOSE_ENV ($_RELEASE)."
        log " Use -f to replace existing config files from examples."
    fi
    log "\n $_ROCKET You can now run: ./install.sh start"
}

# Build all OpenCVE Docker images without using the cache.
docker-build() {
    log "\n--------| Docker compose build"
    display-and-exec "building OpenCVE docker images" docker compose build --no-cache
}

# Start the Docker stack, run migrations, and collect static files.
docker-up() {
    log "\n--------| Docker compose up"
    display-and-exec "starting OpenCVE docker stack" docker compose up -d --build --wait

    log "\n--------| Apply Django webserver DB migration"
    display-and-exec "migrating DB schema with latest changes" -q docker compose exec webserver python manage.py migrate

    log "\n--------| Collect static files from Django webserver"
    display-and-exec "collecting latest static files" -q docker compose exec webserver python manage.py collectstatic --no-input
}

# Delete and recreate an Airflow connection (idempotent).
ensure-airflow-connection() {
    local _CONN_ID="$1"
    shift
    local _ADD_CMD=("docker" "compose" "exec" "airflow-scheduler" "airflow" "connections" "add" "$_CONN_ID" "$@")

    docker compose exec airflow-scheduler airflow connections delete "$_CONN_ID" > /dev/null 2>&1 || true
    display-and-exec "adding $_CONN_ID Airflow connection" -q "${_ADD_CMD[@]}"
}

# Configure PostgreSQL and Redis connections in Airflow.
set-airflow-connections() {
    export $(grep -v '^#' .env | grep -E '^POSTGRES' | tr '\n' ' ')

    log "\n--------| Add Airflow connections"
    ensure-airflow-connection opencve_postgres \
        --conn-uri "postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@postgres:5432/opencve"
    ensure-airflow-connection opencve_redis \
        --conn-uri "redis://redis:6379" --conn-extra '{"db": 3}'

    unset POSTGRES_USER
    unset POSTGRES_PASSWORD
}

# Generate the Django secret key once and store it in the webserver .env file.
init-secret-key() {
    if install-state-is SECRET_KEY_SET; then
        log "> OPENCVE_SECRET_KEY already set (install state), skipping."
        return 0
    fi
    if grep -qE "^OPENCVE_SECRET_KEY=.+" ../web/opencve/conf/.env 2>/dev/null; then
        install-state-set SECRET_KEY_SET true
        log "> OPENCVE_SECRET_KEY already present in .env, skipping."
        return 0
    fi

    log "\n--------| Generate OpenCVE secret key"

    export _OPENCVE_SECRET_KEY=$(docker compose exec webserver python manage.py generate_secret_key | sed -e 's/[&!$]//g')

    display-and-exec "cleaning old OpenCVE secret key" sed -i.bak "s/^OPENCVE_SECRET_KEY=.*/OPENCVE_SECRET_KEY=/g" ../web/opencve/conf/.env
    display-and-exec "updating with new OpenCVE secret key" sed -i.bak "s,^OPENCVE_SECRET_KEY=.*,OPENCVE_SECRET_KEY='$_OPENCVE_SECRET_KEY',g" ../web/opencve/conf/.env && rm -f ../web/opencve/conf/.env.bak

    unset _OPENCVE_SECRET_KEY
    install-state-set SECRET_KEY_SET true
}

# Start the Docker stack and initialize Airflow connections and secret key.
init-docker-stack() {
    docker-up
    set-airflow-connections
    init-secret-key
}

# Clone a KB repository if missing (updates are handled by the OpenCVE DAG).
clone-repo-if-missing() {
    local _URL="$1"
    local _DIR="$2"
    local _NAME="$3"

    if docker compose exec airflow-scheduler test -d "$_DIR/.git" > /dev/null 2>&1; then
        log "> $_NAME repository already present, skipping (updated by the OpenCVE DAG)."
        return 0
    fi

    display-and-exec "cloning $_NAME" docker compose exec airflow-scheduler bash -c "
        if [ -d '$_DIR' ]; then
            echo 'Directory $_DIR exists but is not a git repo' >&2
            exit 1
        fi
        git clone '$_URL' '$_DIR'
    "
}

# Clone all KB repositories into the repositories Docker volume.
clone-repositories() {
    log "\n--------| Initialize OpenCVE repositories"
    clone-repo-if-missing "https://github.com/opencve/opencve-kb.git" "/home/airflow/repositories/opencve-kb" "opencve-kb"
    clone-repo-if-missing "https://github.com/opencve/opencve-nvd.git" "/home/airflow/repositories/opencve-nvd" "opencve-nvd"
    clone-repo-if-missing "https://github.com/opencve/opencve-redhat.git" "/home/airflow/repositories/opencve-redhat" "opencve-redhat"
    clone-repo-if-missing "https://github.com/CVEProject/cvelistV5.git" "/home/airflow/repositories/cvelistV5" "cvelistV5"
    clone-repo-if-missing "https://github.com/cisagov/vulnrichment.git" "/home/airflow/repositories/vulnrichment" "vulnrichment"
    install-state-set CLONED_REPOS true
}

# Import CVEs from the KB into PostgreSQL (one-time operation).
import-opencve-kb() {
    if install-state-is IMPORTED_KB; then
        log "> CVEs already imported (install state), skipping."
        return 0
    fi
    log "\n--------| Import OpenCVE KB inside the database, it can take 10 to 30 min"
    display-and-exec "importing CVEs" docker compose exec webserver python manage.py import_cves
    install-state-set IMPORTED_KB true
}

# Unpause all OpenCVE Airflow DAGs (alias for start-opencve-dag command).
start-opencve-dag() {
    unpause-all-dags
}

# Create the OpenCVE admin user and auto-verify their email address.
create-superuser() {
    if install-state-is SUPERUSER_CREATED; then
        log "> Superuser already created (install state), skipping."
        return 0
    fi

    log "\n--------| Create OpenCVE admin user"
    display-and-exec "creating OpenCVE admin user" docker compose exec -it webserver python manage.py createsuperuser

    export $(grep -v '^#' .env | grep -E '^POSTGRES' | tr '\n' ' ')

    log "\n--------| Auto confirm the created user"
    display-and-exec "confirming the created admin user" -q docker compose exec postgres psql -U "$POSTGRES_USER" -c "INSERT INTO account_emailaddress(email, verified, \"primary\", user_id) SELECT email, 1::bool, 1::bool, id FROM opencve_users ON CONFLICT (user_id, email) DO NOTHING;"

    unset POSTGRES_USER
    unset POSTGRES_PASSWORD
    install-state-set SUPERUSER_CREATED true
}

# Upgrade an existing installation: pull, rebuild, migrate, and restart services.
upgrade-stack() {
    local _RELEASE
    _RELEASE=$(normalize-release "${1:-master}")

    ensure-env-file
    ensure-git-repo

    log "\n$_YELLOW Recommended: back up your PostgreSQL database before upgrading."

    pull-release "$_RELEASE"
    update-opencve-version-in-env "$_RELEASE"

    pause-all-dags
    wait-for-running-dag-runs

    log "\n--------| Start infrastructure services"
    display-and-exec "starting postgres and redis" docker compose up -d postgres redis

    log "\n--------| Rebuild and start webserver"
    display-and-exec "starting webserver" docker compose up -d --build --wait webserver

    log "\n--------| Apply Django webserver DB migration"
    display-and-exec "migrating DB schema with latest changes" -q docker compose exec webserver python manage.py migrate

    log "\n--------| Collect static files from Django webserver"
    display-and-exec "collecting latest static files" -q docker compose exec webserver python manage.py collectstatic --no-input

    verify-container-versions

    log "\n--------| Rebuild and start Airflow and nginx"
    display-and-exec "starting Airflow stack and nginx" docker compose up -d --build --wait \
        airflow-init airflow-webserver airflow-scheduler airflow-worker nginx

    set-airflow-connections
    unpause-all-dags
    install-end
}

# Stop the stack, remove Docker volumes, and clear the install state file.
reset-stack() {
    log "\n$_RED WARNING: This will permanently destroy:"
    log " - All OpenCVE data (PostgreSQL volume: users, CVEs, projects, automations...)"
    log " - Cloned KB repositories (repositories volume)"
    log " - Collected static files (staticfiles volume)"
    log " - Install state (docker/.install-state)"
    log "\n$_YELLOW The following will be KEPT:"
    log " - Config files (docker/.env, web/opencve/conf/.env, settings.py, airflow.cfg)"
    log " - Docker images (faster rebuild on next start)"
    log "\nAfter reset, run: ./install.sh prepare && ./install.sh start"
    log "For fresh configuration files: ./install.sh reset && ./install.sh -f prepare && ./install.sh start"

    if ! $_RESET_CONFIRM; then
        read -r -p "Type 'yes' to confirm destruction: " _CONFIRM
        if [[ "$_CONFIRM" != "yes" ]]; then
            log "$_RED Aborted."
            exit 1
        fi
    fi

    log "\n--------| Stop stack and remove volumes"
    display-and-exec "stopping OpenCVE stack" docker compose down -v

    log "\n--------| Remove install state"
    rm -f "$_INSTALL_STATE_FILE"

    log "\n$_GREEN Reset complete. Run ./install.sh prepare && ./install.sh start to reinstall."
}

# Display a summary of the installation and access URLs.
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

# Display usage information and available commands.
display-usage() {
    local _S1=7
    local _S2=9
    local _BOLD="\033[1m"
    local _NC="\033[0m"

    printf "\n${_BOLD}USAGE${_NC}"
    printf "\n%${_S1}s ./install.sh [OPTIONS] COMMANDS"

    printf "\n\n${_BOLD}OPTIONS${_NC}"
    printf "\n%${_S1}s -h"
    printf "\n%${_S2}s Print usage statement."
    printf "\n%${_S1}s -r"
    printf "\n%${_S2}s Release or branch to install."
    printf "\n%${_S2}s Default: master branch."
    printf "\n%${_S1}s -f"
    printf "\n%${_S2}s Force overwrite of existing configuration files."
    printf "\n%${_S1}s -y"
    printf "\n%${_S2}s Skip confirmation prompts (reset command)."

    printf "\n\n${_BOLD}COMMANDS${_NC}"
    printf "\n%${_S1}s prepare"
    printf "\n%${_S2}s Prepare and add default configuration files for OpenCVE."
    printf "\n%${_S1}s start"
    printf "\n%${_S2}s Start and setup the entire OpenCVE stack. Run after prepare."
    printf "\n%${_S1}s upgrade"
    printf "\n%${_S2}s Upgrade an existing installation (pull, rebuild, migrate)."
    printf "\n%${_S1}s reset"
    printf "\n%${_S2}s Stop stack, remove Docker volumes and install state. Requires confirmation."

    printf "\n\n${_BOLD}SPECIFIC COMMANDS${_NC}"
    printf "\n%${_S1}s add-config-files"
    printf "\n%${_S2}s Add default configurations files."
    printf "\n%${_S1}s init-docker-stack"
    printf "\n%${_S2}s Perform docker compose up for OpenCVE stack and initialize connections."
    printf "\n%${_S1}s clone-repositories"
    printf "\n%${_S2}s Clone KB repositories into the repositories Docker volume."
    printf "\n%${_S1}s create-superuser"
    printf "\n%${_S2}s Create an OpenCVE super user with admin privileges."
    printf "\n%${_S1}s import-opencve-kb"
    printf "\n%${_S2}s Import OpenCVE KB inside local database. One-time operation."
    printf "\n%${_S1}s start-opencve-dag"
    printf "\n%${_S2}s Unpause all OpenCVE DAGs in Airflow."
    printf "\n%${_S1}s docker-up"
    printf "\n%${_S2}s Perform docker compose up with OpenCVE stack."
    printf "\n%${_S1}s docker-build"
    printf "\n%${_S2}s Build the docker images for OpenCVE stack."
    printf "\n%${_S1}s init-secret-key"
    printf "\n%${_S2}s Generate OpenCVE Django secret key."

    printf "\n\n${_BOLD}EXAMPLES${_NC}"
    printf "\n%${_S1}s ./install.sh"
    printf "\n%${_S2}s Equivalent to ./install.sh prepare."
    printf "\n%${_S1}s ./install.sh start"
    printf "\n%${_S2}s Start and setup the entire OpenCVE stack."
    printf "\n%${_S1}s ./install.sh -r master prepare"
    printf "\n%${_S2}s Prepare configuration files for the master branch."
    printf "\n%${_S1}s ./install.sh upgrade"
    printf "\n%${_S2}s Upgrade to the latest master branch."
    printf "\n%${_S1}s ./install.sh -r v3.0.0 upgrade"
    printf "\n%${_S2}s Upgrade to a specific release tag."
    printf "\n%${_S1}s ./install.sh reset"
    printf "\n%${_S2}s Destroy all data and reinstall from scratch (interactive confirmation)."
    printf "\n%${_S1}s ./install.sh reset && ./install.sh -f prepare && ./install.sh start"
    printf "\n%${_S2}s Full reset including fresh configuration files."

    printf "\n\n${_BOLD}DOCUMENTATION${_NC}"
    printf "\n%${_S1}s https://docs.opencve.io/deployment/"
    printf "\n"
}

_RELEASE="master"
_FORCE=false
_RESET_CONFIRM=false
OPTSTRING=":r:fhy"
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
        y)
            _RESET_CONFIRM=true
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
        ensure-version-consistency
        init-docker-stack
        clone-repositories
        import-opencve-kb
        verify-container-versions
        start-opencve-dag
        create-superuser
        install-end
        ;;
    "upgrade" )
        upgrade-stack "$_RELEASE"
        ;;
    "reset" )
        reset-stack
        ;;
    "add-config-files" )
        add-config-files "$_RELEASE"
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
