# Define build arguments for Airflow and Python versions
ARG AIRFLOW_VERSION="2.8.4"
ARG PYTHON_VERSION="3.11"
ARG AIRFLOW_IMAGE="apache/airflow:slim-${AIRFLOW_VERSION}-python${PYTHON_VERSION}"

# Use Airflow as the base image
FROM ${AIRFLOW_IMAGE}

# Display the versions being used during the build
RUN echo "Building with Airflow version ${AIRFLOW_VERSION} and Python version ${PYTHON_VERSION}"

# Switch to root for system-level operations
USER root

# Update, upgrade, install git, and clean up unnecessary files
RUN echo "Updating package lists and installing required packages" \
    && apt-get update \
    && ACCEPT_EULA=Y apt-get upgrade -y \
    && ACCEPT_EULA=Y apt-get install -y git \
    && echo "Cleaning up package lists to reduce image size" \
    && rm -rf /var/lib/apt/lists/*

# Switch to airflow user
USER airflow

# Create necessary directories
RUN mkdir -p /home/airflow/repositories

# Copy the Python dependencies file earlier to take advantage of Docker's cache
COPY requirements.txt /

# Upgrade pip and install the required Python packages without caching
RUN python3 -m pip install --upgrade pip \
    && echo "Installing dependencies from requirements.txt" \
    && pip install --no-cache-dir -r /requirements.txt
