ARG AIRFLOW_VERSION="2.10.4"
ARG PYTHON_VERSION="3.11"
ARG AIRFLOW_IMAGE="apache/airflow:slim-${AIRFLOW_VERSION}-python${PYTHON_VERSION}"

ARG OPENCVE_REPOSITORY="https://github.com/opencve/opencve.git"
ARG OPENCVE_VERSION="master"

FROM ${AIRFLOW_IMAGE} AS base

USER root

RUN apt-get update \
    && ACCEPT_EULA=Y apt-get upgrade -y \
    && ACCEPT_EULA=Y apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

FROM base AS opencve-source

ARG OPENCVE_REPOSITORY
ARG OPENCVE_VERSION

RUN git clone --depth 1 -b "${OPENCVE_VERSION}" --single-branch "${OPENCVE_REPOSITORY}" /tmp/opencve

FROM base

ARG OPENCVE_REPOSITORY
ARG OPENCVE_VERSION

LABEL org.opencve.version="${OPENCVE_VERSION}"
LABEL org.opencve.repository="${OPENCVE_REPOSITORY}"

COPY --from=opencve-source /tmp/opencve/scheduler/requirements.txt /requirements.txt

USER airflow

RUN mkdir -p /home/airflow/repositories

RUN python3 -m pip install --upgrade pip \
    && pip install --no-cache-dir -r /requirements.txt

USER root

COPY --from=opencve-source --chown=airflow:root /tmp/opencve/scheduler/dags/ /opt/airflow/dags/

USER airflow
