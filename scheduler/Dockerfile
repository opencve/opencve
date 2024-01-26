ARG AIRFLOW_VERSION="2.8.0"
ARG PYTHON_VERSION="3.11"
ARG AIRFLOW_IMAGE="apache/airflow:slim-${AIRFLOW_VERSION}-python${PYTHON_VERSION}"

FROM ${AIRFLOW_IMAGE}

USER root

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

USER airflow

COPY requirements.txt /

RUN python3 -m pip install --upgrade pip
RUN pip install --no-cache-dir -r /requirements.txt

