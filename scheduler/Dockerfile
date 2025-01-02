ARG AIRFLOW_VERSION="2.10.4"
ARG PYTHON_VERSION="3.11"
ARG AIRFLOW_IMAGE="apache/airflow:slim-${AIRFLOW_VERSION}-python${PYTHON_VERSION}"

FROM ${AIRFLOW_IMAGE}

USER root

RUN apt-get update \
    && ACCEPT_EULA=Y apt-get upgrade -y \
    && ACCEPT_EULA=Y apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

USER airflow

RUN mkdir -p /home/airflow/repositories

COPY requirements.txt /

RUN python3 -m pip install --upgrade pip
RUN pip install --no-cache-dir -r /requirements.txt
