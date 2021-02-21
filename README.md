<p align="center">
  <img alt="OpenCVE" src="https://raw.githubusercontent.com/opencve/opencve/master/logo.png">
</p>
<p align="center">
  <a href="https://github.com/opencve/opencve/actions?query=workflow%3ATests"><img alt="Tests" src="https://github.com/opencve/opencve/workflows/Tests/badge.svg"></a>
  <a href="https://www.python.org/"><img alt="Python versions" src="https://img.shields.io/badge/python-3.6%2B-blue.svg"></a>
  <a href="https://github.com/python/black"><img alt="Code style: black" src="https://img.shields.io/badge/code%20style-black-000000.svg"></a>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/opencve/opencve/master/opencve1.png" width="300">
  <img src="https://raw.githubusercontent.com/opencve/opencve/master/opencve2.png" width="300">
  <img src="https://raw.githubusercontent.com/opencve/opencve/master/opencve3.png" width="300">
  <img src="https://raw.githubusercontent.com/opencve/opencve/master/opencve4.png" width="300">
</p>

----------------

**OpenCVE**, formerly known as *Saucs*, is a platform used to locally import the list of CVEs and perform searches on it (by vendors, products, CVSS, CWE...).

Users subscribe to vendors or products, and OpenCVE alerts them when a new CVE is created or when an update is done in an existing CVE.

## How does it work

OpenCVE uses the [JSON feed](https://nvd.nist.gov/vuln/data-feeds#JSON_FEED) provided by the [NVD](https://nvd.nist.gov/) to update the local list of CVEs.

After an initial import, a background task is regularly executed to synchronize the local copy with the NVD feed. If a new CVE is added, or if a change is detected, the subscribers of the related vendors and products are alerted.

For now the only method of notification is the mail, but we plan to add other integrations (webhooks, Slack, Jira, PagerDuty, OpsGenie...).

## Requirements

OpenCVE works with **Python >=3.6**.

It uses the JSONB feature for performance, so you will need a **PostgreSQL** instance to store the data (CVE, Users, Vendors, Products, Subscriptions, ...). Other engines are not supported.

Celery is used to periodically fetch the NVD database and update the list of CVEs. For that you will need a broker : we recommend you **Redis** for the ease of installation. Futhermore it is possible that future versions of OpenCVE will use a cache feature, in that case the Redis requirement will already be filled for you.

During the import of initial data OpenCVE will download and parse huge files, like the CPE dictionnary. For that we recommend you **3.5G RAM** at least.

## Installation

You can install OpenCVE either using Docker with our [dedicated repository](https://github.com/opencve/opencve-docker) or using `pip` with the following procedure :

```
$ pip install opencve
```

### Configuration file

The first step is to create the configuration file. You can do it with the `init` command :

```
$ opencve init
[*] Configuration created in /Users/ncrocfer/opencve/opencve.cfg
```

**Note:** a custom path can be specified in the `OPENCVE_CONFIG` environment variable.

### Initialize the database

The database can be configured using the `database_uri` variable of the `opencve.cfg` file. Once done the `upgrade-db` command will create all the tables :

```
$ opencve upgrade-db
```

**Note:** because it uses the JSONB feature for performance, OpenCVE only supports PostgreSQL.

### Import the data

The database is now created, we need to populate it using the `import-data` command :

```
$ opencve import-data
```

This command can take several minutes, mainly for the list of vendors and products (around 10mn), so be patient :) But don't worry you will only do it once.

### Start the workers

The synchronization between the OpenCVE database and the CVE list is done using a periodic Celery task.

A worker and the scheduler must be started for that (don't forget to configure the Celery configuration in the `opencve.cfg` file) :

```
$ opencve celery worker -l INFO
$ opencve celery beat -l INFO
```

### Create an admin

```
$ opencve create-user john john.doe@example.com --admin
Password:
Repeat for confirmation:
[*] User john created.
```

### Start the webserver

You can finally launch the webserver and visit OpenCVE at `localhost:8000` :

```
$ opencve webserver
[2020-07-14 20:38:06 +0200] [16032] [INFO] Starting gunicorn 20.0.4
[2020-07-14 20:38:06 +0200] [16032] [INFO] Listening at: http://127.0.0.1:8000 (16032)
[2020-07-14 20:38:06 +0200] [16032] [INFO] Using worker: sync
[2020-07-14 20:38:06 +0200] [16040] [INFO] Booting worker with pid: 16040
```

**Note:** the server name can be configured in the `opencve.cfg` file with the `server_name` variable.
