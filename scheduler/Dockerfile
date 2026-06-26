ARG AIRFLOW_VERSION="2.10.4"
ARG PYTHON_VERSION="3.12"
ARG AIRFLOW_IMAGE="apache/airflow:slim-${AIRFLOW_VERSION}-python${PYTHON_VERSION}"

FROM ${AIRFLOW_IMAGE} AS builder

USER root

RUN apt-get update \
    && ACCEPT_EULA=Y apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ARG OPENCVE_REPOSITORY="https://github.com/opencve/opencve.git"
ARG OPENCVE_VERSION="master"

RUN git clone --depth 1 -b "${OPENCVE_VERSION}" --single-branch "${OPENCVE_REPOSITORY}"

FROM ${AIRFLOW_IMAGE}

USER root

RUN apt-get update \
    && ACCEPT_EULA=Y apt-get upgrade -y \
    && ACCEPT_EULA=Y apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

ARG OPENCVE_VERSION="master"

ENV OPENCVE_VERSION=${OPENCVE_VERSION}

COPY --from=builder --chown=airflow:root /app/opencve/scheduler/dags/ /opt/airflow/dags/
COPY --chown=airflow:root requirements.txt /requirements.txt

USER airflow

RUN mkdir -p /home/airflow/repositories \
    && pip install --no-cache-dir -r /requirements.txt
