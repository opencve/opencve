FROM python:3.11-slim-bookworm as base

# Builder
FROM base as builder

ARG OPENCVE_REPOSITORY="https://github.com/opencve/opencve.git"
ARG OPENCVE_VERSION="master"

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN git clone --depth 1 -b "${OPENCVE_VERSION}" --single-branch "${OPENCVE_REPOSITORY}"

RUN python3 -m venv /app/venv

ENV PATH="/app/venv/bin:$PATH"

RUN python3 -m pip install --upgrade pip

RUN python3 -m pip install -r opencve/web/requirements.txt

# OpenCVE Image
FROM base

ARG OPENCVE_REPOSITORY

LABEL name="opencve"
LABEL maintainer="dev@opencve.io"
LABEL url="${OPENCVE_REPOSITORY}"

RUN apt-get update && apt-get upgrade -y && apt-get install -y\
    git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/ /app/

ENV PATH="/app/venv/bin:$PATH"

WORKDIR /app/opencve/web/

EXPOSE 8000

ENTRYPOINT ["python3"]
CMD ["manage.py", "runserver", "0.0.0.0:8000"]

