OpenCVE
-------

OpenCVE (formerly known as Saucs) is a platform that alerts you about new vulnerabilities related to the CVE list.

## How does it work

OpenCVE uses the [JSON feed](https://nvd.nist.gov/vuln/data-feeds#JSON_FEED) provided by the [NVD](https://nvd.nist.gov/) to be synchronized.

After an initial import, a background task is regularly executed to check changes in the list. If a new CVE is added, or if a change is detected, the subscribers of the related vendors and products will be alerted.

For now the only method of notification is the mail, but we plan to add other integrations (webhooks, Slack, Jira, PagerDuty, OpsGenie...).

## Installation

OpenCVE can simply be installed using `pip` :

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
$ opencve create-user john john.doe@example.com P4ssw0rd --admin
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

## Screenshots

![OpenCVE 1](../master/opencve1.png?raw=true)

![OpenCVE 2](../master/opencve2.png?raw=true)

![OpenCVE 3](../master/opencve3.png?raw=true)

![OpenCVE 4](../master/opencve4.png?raw=true)