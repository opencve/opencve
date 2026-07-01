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
#   -y                Skip confirmation prompts (reset and upgrade commands).
#
# Commands:
#   prepare           Prepare and add default configuration files for OpenCVE.
#   start             Start and set up the entire OpenCVE stack.
#   upgrade           Upgrade an existing installation (rebuild images, migrate).
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
#   Ensure that the following commands are available: docker, sed, grep, tr.

_GREEN="\360\237\237\242"
_YELLOW="\360\237\237\241"
_RED="\342\235\214"
_BYE="\360\237\221\213"
_DONE="\342\234\205"
_ROCKET="\360\237\232\200"

_AIRFLOW_DAGS=(opencve summarize_reports sync_weaknesses clean_reports)

# Check for required commands
required_commands=("docker" "sed" "grep" "tr")
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

_STEP_CURRENT=0
_STEP_TOTAL=0

# Initialize step counter for the current command (X in n/X progress).
begin-steps() {
    _STEP_TOTAL=$1
    _STEP_CURRENT=0
}

# Log a numbered installation step header.
step-header() {
    local _TITLE="$1"
    _STEP_CURRENT=$((_STEP_CURRENT + 1))
    log "\n--------| $_TITLE (${_STEP_CURRENT}/${_STEP_TOTAL})"
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

# Normalize release aliases (latest is the same as master).
normalize-release() {
    local _RELEASE="$1"
    if [[ "$_RELEASE" == "latest" ]]; then
        _RELEASE="master"
    fi
    if [[ ! "$_RELEASE" =~ ^[a-zA-Z0-9._/-]+$ ]]; then
        log "$_RED ERROR: invalid release '$_RELEASE' (allowed: letters, digits, ., _, /, -)."
        exit 1
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

# Read a single key=value from docker/.env.
read-env-var() {
    local _KEY="$1"
    local _VAL
    _VAL=$(grep -E "^[[:space:]]*${_KEY}=" .env 2>/dev/null | tail -n 1 | cut -d= -f2-)
    [[ -n "$_VAL" ]] || return 1
    _VAL="${_VAL#\"}"; _VAL="${_VAL%\"}"
    _VAL="${_VAL#\'}"; _VAL="${_VAL%\'}"
    printf '%s' "$_VAL"
}

# Verify webserver and scheduler containers match OPENCVE_VERSION from .env.
verify-container-versions() {
    step-header "Verify container versions"
    ensure-env-file
    local _EXPECTED
    _EXPECTED=$(read-env-var OPENCVE_VERSION || true)

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

# Update OPENCVE_VERSION in docker/.env.
update-opencve-version-in-env() {
    step-header "Update OpenCVE version in .env"
    local _RELEASE="$1"
    _RELEASE=$(normalize-release "$_RELEASE")
    ensure-env-file
    display-and-exec "updating OpenCVE environment release version to $_RELEASE" sed -i.bak "s,OPENCVE_VERSION=.*,OPENCVE_VERSION=$_RELEASE,g" "./.env" && rm -f "./.env.bak"
}

# Pause all OpenCVE Airflow DAGs.
pause-all-dags() {
    step-header "Pause Airflow DAGs"
    local _DAG
    for _DAG in "${_AIRFLOW_DAGS[@]}"; do
        docker compose exec airflow-scheduler airflow dags pause "$_DAG" > /dev/null 2>&1 || true
    done
    log "> all DAGs paused $_DONE"
}

# Unpause all OpenCVE Airflow DAGs.
unpause-all-dags() {
    step-header "Unpause Airflow DAGs"
    local _DAG
    for _DAG in "${_AIRFLOW_DAGS[@]}"; do
        display-and-exec "unpausing $_DAG dag" -q docker compose exec airflow-scheduler airflow dags unpause "$_DAG"
    done
}

# Wait for running Airflow DAG tasks to finish before upgrading.
wait-for-running-dag-runs() {
    local _TIMEOUT=300
    local _ELAPSED=0
    step-header "Wait for running DAG tasks to finish"
    while [[ $_ELAPSED -lt $_TIMEOUT ]]; do
        local _RUNNING=0
        local _DAG _OUTPUT _COUNT
        for _DAG in "${_AIRFLOW_DAGS[@]}"; do
            _OUTPUT=$(docker compose exec -T airflow-scheduler airflow dags list-runs -d "$_DAG" --state running -o plain 2>/dev/null || true)
            _COUNT=$(printf '%s\n' "$_OUTPUT" | awk 'NR>1 && NF { count++ } END { print count+0 }')
            _RUNNING=$((_RUNNING + _COUNT))
        done
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

    step-header "Find the release to install"
    if [[ $_MAJOR_VERSION =~ ^[v0-1|0-1.]+$ ]]; then
        log "$_RED ERROR: this script works only for release >= 2.0.0, release given: $_RELEASE"
        exit 1
    fi
    log "> OpenCVE version $_RELEASE will be baked into Docker images at build time."

    step-header "Airflow configuration"
    is-present "$_AIRFLOW_CONFIG_FILE"
    if [[ $? == 0 ]]; then
        display-and-exec "copying airflow config file" cp "$_AIRFLOW_CONFIG_FILE.example" "$_AIRFLOW_CONFIG_FILE"
        local _START_DATE
        _START_DATE=$(date '+%Y-%m-%d')
        display-and-exec "updating start date for opencve dag" sed -i.bak "s/start_date = .*/start_date = $_START_DATE/g" "$_AIRFLOW_CONFIG_FILE" && rm -f "$_AIRFLOW_CONFIG_FILE.bak"
        display-and-exec "updating start date for summarize_reports dag" sed -i.bak "s/start_date_summarize_reports = .*/start_date_summarize_reports = $_START_DATE/g" "$_AIRFLOW_CONFIG_FILE" && rm -f "$_AIRFLOW_CONFIG_FILE.bak"
        display-and-exec "updating start date for sync_weaknesses dag" sed -i.bak "s/start_date_sync_weaknesses = .*/start_date_sync_weaknesses = $_START_DATE/g" "$_AIRFLOW_CONFIG_FILE" && rm -f "$_AIRFLOW_CONFIG_FILE.bak"
        local _CONFIGURED_START_DATE
        _CONFIGURED_START_DATE=$(grep '^start_date' "$_AIRFLOW_CONFIG_FILE")
        log "\nConfigured start date:\n$_CONFIGURED_START_DATE"
    else
        _CONFIG_BLOCKED=true
    fi

    step-header "Django settings and .env file"
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

    step-header "Docker compose .env file"
    is-present "$_DOCKER_COMPOSE_ENV"
    if [[ $? == 0 ]]; then
        display-and-exec "copying Docker compose env file" cp "./conf/$_DOCKER_COMPOSE_ENV.example" "$_DOCKER_COMPOSE_ENV"
    else
        _CONFIG_BLOCKED=true
    fi

    update-opencve-version-in-env "$_RELEASE"

    step-header "Nginx OpenCVE template"
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
        log "\n $_YELLOW Some configuration files already exist. OPENCVE_VERSION was updated in $_DOCKER_COMPOSE_ENV ($_RELEASE)."
        log " Use -f to replace existing config files from examples."
    fi
    log "\n $_ROCKET You can now run: ./install.sh start"
}

# Build all OpenCVE Docker images without using the cache.
docker-build() {
    step-header "Docker compose build"
    display-and-exec "building OpenCVE docker images" docker compose build --no-cache
}

# Start the Docker stack, run migrations, and collect static files.
docker-up() {
    step-header "Docker compose up"
    display-and-exec "starting OpenCVE docker stack" docker compose up -d --build --wait

    step-header "Apply Django webserver DB migration"
    display-and-exec "migrating DB schema with latest changes" -q docker compose exec webserver python manage.py migrate

    step-header "Collect static files from Django webserver"
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
    local _POSTGRES_USER _POSTGRES_PASSWORD _POSTGRES_URI
    _POSTGRES_USER=$(read-env-var POSTGRES_USER)
    _POSTGRES_PASSWORD=$(read-env-var POSTGRES_PASSWORD)
    _POSTGRES_URI="postgres://${_POSTGRES_USER}:${_POSTGRES_PASSWORD}@postgres:5432/opencve"

    step-header "Add Airflow connections"
    ensure-airflow-connection opencve_postgres \
        --conn-uri "$_POSTGRES_URI"
    ensure-airflow-connection opencve_redis \
        --conn-uri "redis://redis:6379" --conn-extra '{"db": 3}'
}

# Generate the Django secret key once and store it in the webserver .env file.
init-secret-key() {
    step-header "Generate OpenCVE secret key"
    local _ENV_FILE="../web/opencve/conf/.env"
    if grep -qE "^OPENCVE_SECRET_KEY=.+" "$_ENV_FILE" 2>/dev/null; then
        log "> OPENCVE_SECRET_KEY already present in .env, skipping."
        return 0
    fi

    local _OPENCVE_SECRET_KEY _ESCAPED_KEY
    _OPENCVE_SECRET_KEY=$(docker compose exec webserver python manage.py generate_secret_key)
    _ESCAPED_KEY="${_OPENCVE_SECRET_KEY//\'/\'\\\'\'}"

    log "> updating OpenCVE secret key..."
    grep -v '^OPENCVE_SECRET_KEY=' "$_ENV_FILE" > "${_ENV_FILE}.tmp"
    printf 'OPENCVE_SECRET_KEY=%s\n' "'${_ESCAPED_KEY}'" >> "${_ENV_FILE}.tmp"
    mv "${_ENV_FILE}.tmp" "$_ENV_FILE"
    log "> done $_DONE"
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
    step-header "Initialize OpenCVE repositories"
    clone-repo-if-missing "https://github.com/opencve/opencve-kb.git" "/home/airflow/repositories/opencve-kb" "opencve-kb"
    clone-repo-if-missing "https://github.com/opencve/opencve-nvd.git" "/home/airflow/repositories/opencve-nvd" "opencve-nvd"
    clone-repo-if-missing "https://github.com/opencve/opencve-redhat.git" "/home/airflow/repositories/opencve-redhat" "opencve-redhat"
    clone-repo-if-missing "https://github.com/CVEProject/cvelistV5.git" "/home/airflow/repositories/cvelistV5" "cvelistV5"
    clone-repo-if-missing "https://github.com/cisagov/vulnrichment.git" "/home/airflow/repositories/vulnrichment" "vulnrichment"
}

# Import CVEs from the KB into PostgreSQL (one-time operation).
import-opencve-kb() {
    step-header "Import OpenCVE KB inside the database, it can take 10 to 30 min"
    local _POSTGRES_USER
    _POSTGRES_USER=$(read-env-var POSTGRES_USER)
    if docker compose exec -T postgres psql -U "$_POSTGRES_USER" -tAc \
        "SELECT 1 FROM opencve_cves LIMIT 1" 2>/dev/null | grep -q 1; then
        log "> CVEs already imported in database, skipping."
        return 0
    fi
    display-and-exec "importing CVEs" docker compose exec webserver python manage.py import_cves
}

# Unpause all OpenCVE Airflow DAGs (alias for start-opencve-dag command).
start-opencve-dag() {
    unpause-all-dags
}

# Create the OpenCVE admin user and auto-verify their email address.
create-superuser() {
    local _SKIP=false
    local _POSTGRES_USER
    _POSTGRES_USER=$(read-env-var POSTGRES_USER)

    if docker compose exec -T postgres psql -U "$_POSTGRES_USER" -tAc \
        "SELECT 1 FROM opencve_users WHERE is_superuser LIMIT 1" 2>/dev/null | grep -q 1; then
        _SKIP=true
    fi

    step-header "Create OpenCVE admin user"
    if $_SKIP; then
        log "> Superuser already exists in database, skipping."
    else
        display-and-exec "creating OpenCVE admin user" docker compose exec -it webserver python manage.py createsuperuser
    fi

    step-header "Auto confirm the created user"
    if $_SKIP; then
        log "> Superuser already exists in database, skipping."
        return 0
    fi

    display-and-exec "confirming the created admin user" -q docker compose exec postgres psql -U "$_POSTGRES_USER" -c "INSERT INTO account_emailaddress(email, verified, \"primary\", user_id) SELECT email, 1::bool, 1::bool, id FROM opencve_users ON CONFLICT (user_id, email) DO NOTHING;"
}

# Upgrade an existing installation: rebuild images at OPENCVE_VERSION and migrate.
upgrade-stack() {
    local _RELEASE
    _RELEASE=$(normalize-release "${1:-master}")

    ensure-env-file

    log "\n$_YELLOW Recommended: back up your PostgreSQL database before upgrading."

    if ! $_SKIP_CONFIRM; then
        read -r -p "Type 'yes' to continue upgrade: " _CONFIRM
        if [[ "$_CONFIRM" != "yes" ]]; then
            log "$_RED Aborted."
            exit 1
        fi
    fi

    update-opencve-version-in-env "$_RELEASE"

    pause-all-dags
    wait-for-running-dag-runs

    step-header "Start infrastructure services"
    display-and-exec "starting postgres and redis" docker compose up -d postgres redis

    step-header "Rebuild and start webserver"
    display-and-exec "starting webserver" docker compose up -d --build --wait webserver

    step-header "Apply Django webserver DB migration"
    display-and-exec "migrating DB schema with latest changes" -q docker compose exec webserver python manage.py migrate

    step-header "Collect static files from Django webserver"
    display-and-exec "collecting latest static files" -q docker compose exec webserver python manage.py collectstatic --no-input

    step-header "Rebuild and start Airflow and nginx"
    display-and-exec "starting Airflow stack and nginx" docker compose up -d --build --wait \
        airflow-init airflow-webserver airflow-scheduler airflow-worker nginx

    verify-container-versions

    set-airflow-connections
    unpause-all-dags
    install-end
}

# Stop the stack and remove Docker volumes.
reset-stack() {
    log "\n$_RED WARNING: This will permanently destroy:"
    log " - All OpenCVE data (PostgreSQL volume: users, CVEs, projects, automations...)"
    log " - Cloned KB repositories (repositories volume)"
    log " - Collected static files (staticfiles volume)"
    log "\n$_YELLOW The following will be KEPT:"
    log " - Config files (docker/.env, docker/conf/*.conf.template, web/opencve/conf/.env, web/opencve/conf/settings.py, scheduler/airflow.cfg)"
    log " - Docker images (faster rebuild on next start)"
    log "\nAfter reset, run: ./install.sh prepare && ./install.sh start"
    log "For fresh configuration files: ./install.sh reset && ./install.sh -f prepare && ./install.sh start"

    if ! $_SKIP_CONFIRM; then
        read -r -p "Type 'yes' to confirm destruction: " _CONFIRM
        if [[ "$_CONFIRM" != "yes" ]]; then
            log "$_RED Aborted."
            exit 1
        fi
    fi

    begin-steps 1

    step-header "Stop stack and remove volumes"
    display-and-exec "stopping OpenCVE stack" docker compose down -v

    log "\n$_GREEN Reset complete. Run ./install.sh prepare && ./install.sh start to reinstall."
}

# Display a summary of the installation and access URLs.
install-end() {
    local _OPENCVE_PORT _OPENCVE_VERSION _AIRFLOW_PORT _AIRFLOW_USER _AIRFLOW_PASS
    _OPENCVE_PORT=$(read-env-var OPENCVE_PORT || true)
    _OPENCVE_VERSION=$(read-env-var OPENCVE_VERSION || true)
    _AIRFLOW_PORT=$(read-env-var AIRFLOW_WEBSERVER_PORT || true)
    _AIRFLOW_USER=$(read-env-var _AIRFLOW_WWW_USER_USERNAME || true)
    _AIRFLOW_PASS=$(read-env-var _AIRFLOW_WWW_USER_PASSWORD || true)
    _OPENCVE_PORT="${_OPENCVE_PORT:-80}"
    _OPENCVE_VERSION="${_OPENCVE_VERSION:-unknown}"
    _AIRFLOW_PORT="${_AIRFLOW_PORT:-8080}"
    _AIRFLOW_USER="${_AIRFLOW_USER:-airflow}"
    _AIRFLOW_PASS="${_AIRFLOW_PASS:-airflow}"

    log "\n\n$_GREEN Everything is set up, you can now access to OpenCVE locally:"
    log "- on port $_OPENCVE_PORT for OpenCVE web instance"
    log " You can login with your account and password set at the previous step 'Create OpenCVE admin user'."
    log " You can set a new one with the following command: ./install.sh create-superuser"
    log " The installed version is: $_OPENCVE_VERSION"
    log "- on port $_AIRFLOW_PORT for OpenCVE Airflow scheduler"
    log " You can login with the username \"$_AIRFLOW_USER\" and password \"$_AIRFLOW_PASS\"."

    log "\n $_BYE Installation complete! Thank you for choosing OpenCVE!"
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
    printf "\n%${_S2}s Skip confirmation prompts (reset and upgrade commands)."

    printf "\n\n${_BOLD}COMMANDS${_NC}"
    printf "\n%${_S1}s prepare"
    printf "\n%${_S2}s Prepare and add default configuration files for OpenCVE."
    printf "\n%${_S1}s start"
    printf "\n%${_S2}s Start and setup the entire OpenCVE stack. Run after prepare."
    printf "\n%${_S1}s upgrade"
    printf "\n%${_S2}s Upgrade an existing installation (rebuild images, migrate). Requires confirmation."
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
_SKIP_CONFIRM=false
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
            _SKIP_CONFIRM=true
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
        begin-steps 6
        add-config-files "$_RELEASE"
        ;;
    "start" )
        begin-steps 11
        init-docker-stack
        clone-repositories
        import-opencve-kb
        verify-container-versions
        start-opencve-dag
        create-superuser
        install-end
        ;;
    "upgrade" )
        begin-steps 11
        upgrade-stack "$_RELEASE"
        ;;
    "reset" )
        reset-stack
        ;;
    "add-config-files" )
        begin-steps 6
        add-config-files "$_RELEASE"
        ;;
    "init-docker-stack" )
        begin-steps 5
        init-docker-stack
        ;;
    "clone-repositories" )
        begin-steps 1
        clone-repositories
        ;;
    "import-opencve-kb" )
        begin-steps 1
        import-opencve-kb
        ;;
    "start-opencve-dag" )
        begin-steps 1
        start-opencve-dag
        ;;
    "create-superuser" )
        begin-steps 2
        create-superuser
        ;;
    "docker-up" )
        begin-steps 3
        docker-up
        ;;
    "docker-build" )
        begin-steps 1
        docker-build
        ;;
    "init-secret-key" )
        begin-steps 1
        init-secret-key
        ;;
    "bye" )
        install-end
        ;;
    "" )
        begin-steps 6
        add-config-files "$_RELEASE"
        ;;
    * )
        display-usage
        ;;
esac
