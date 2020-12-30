FROM python:3.6-alpine AS builder
LABEL maintainer "Luc Michalski <lmichalski@evolutive-business.com"

WORKDIR /opt/app

# Install Python and external dependencies, including headers and GCC
RUN apk add --no-cache libffi libffi-dev musl-dev gcc g++ git ca-certificates postgresql-dev

# Update Pip3 
RUN python3 -m pip install --upgrade pip

# Install Pipenv
RUN pip3 install pipenv

# Create a virtual environment and activate it
RUN python3 -m venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH" \
	VIRTUAL_ENV="/opt/venv"

COPY requirements.txt .

# Install dependencies into the virtual environment with Pipenv
RUN python3 -m pip install --upgrade pip
RUN pip3 install -r requirements.txt

FROM python:3.6-alpine
MAINTAINER Luc Michalski <michalski.luc@gmail.com>

ARG VERSION
ARG BUILD
ARG NOW
ARG TINI_VERSION=${TINI_VERSION:-"v0.19.0"}

# Install tini to /usr/local/sbin
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-muslc-amd64 /usr/local/sbin/tini

# Install runtime dependencies & create runtime user
RUN apk --no-cache --no-progress add ca-certificates openssl libffi openblas libstdc++ postgresql-client \
    && chmod +x /usr/local/sbin/tini && mkdir -p /opt \
    && adduser -D opencve -h /opt/opencve -s /bin/sh \
    && su opencve -c 'cd /opt/opencve; mkdir -p bin config data logs'

# Switch to user context
# USER opencve
WORKDIR /opt/opencve

# Copy the virtual environment from the previous image
COPY --from=builder /opt/venv /opt/venv

# Copy sources
COPY . .

# Activate the virtual environment
ENV PATH="/opt/venv/bin:$PATH" \
    VIRTUAL_ENV="/opt/venv"

# Set container labels
LABEL name="opencve" \
      version="$VERSION" \
      build="$BUILD" \
      architecture="x86_64" \
      build_date="$NOW" \
      vendor="opencve" \
      maintainer="Luc Michalski <lmichalski@evolutive-business.com>" \
      url="https://github.com/opencve/opencve" \
      summary="OpenCVE project with Docker" \
      description="OpenCVE project with Docker" \
      vcs-type="git" \
      vcs-url="https://github.com/opencve/opencve" \
      vcs-ref="$VERSION" \
      distribution-scope="public"

# Container configuration
EXPOSE 5000
VOLUME ["/opt/opencve/data"]
ENTRYPOINT ["tini", "-g", "--", "./docker-entrypoint.sh"]
