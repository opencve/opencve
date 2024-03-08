# OpenCVE self-hosted docker

You can install the complete stack with docker containing all the services you need to run OpenCVE:
- OpenCVE webserver
- Airflow instances
- Redis
- PostgreSQL

The script regroups and follows the steps described in the web and scheduler install documentations.

## Requirements

You need to have your server installed with Debian or equivalent, with Docker v25.0.x and docker-compose plugin.
The precedure is run as root.

## Installation

There is an installation script that helps you configure your server.
Run the script without option to get help:

```
cd docker
./install.sh
```

There are 2 options that run all the commands for you:
- prepare
- start

You can run dedicated commands if you want to proceed step by step:
```
 set-user           : Install airflow user
 clone-repositories : Clone KB repositories
 add-config-files   : Add default configurations files
 start-docker-stack : Start docker compose stack
 import-opencve-kb  : Import OpenCVE KB inside local database
 start-opencve-dag  : Unpause OpenCVE Dag in Airflow
```

##  Installation step by step

### Setup airflow user

```
./install.sh set-user
--> Creating airflow user
id: ‘airflow’: no such user
--> Creating airflow directories
Done
```

### Clone repositories

```
./install.sh clone-repositories
--> Cloning OpenCVE needed repositories
Cloning into '/home/airflow/repositories/opencve-kb'...
[...]
Cloning into '/home/airflow/repositories/opencve-nvd'...
[...]
Cloning into '/home/airflow/repositories/cvelistV5'...
[...]
```

### Add the configuration files

```
./install.sh add-config-files
--> Adding airflow config file
--> Adding Django settings file
--> Copying .env file for docker compose
--> Copying opencve.conf.template for Nginx
Don't forget to update the .env and settings.py files with your inputs before starting the docker compose stack
```

First, you need to verify and update your env file:

```
cat .env
```

It's advised to change the following variables:
```
POSTGRES_PASSWORD
_AIRFLOW_WWW_USER_USERNAME
_AIRFLOW_WWW_USER_PASSWORD
AIRFLOW__CORE__FERNET_KEY
```

:warning: You need to set the above env variables before starting OpenCVE  stack as they are configured at the first run of docker compose.

To customize the fernet key: [how to generate a new fernet key](https://airflow.apache.org/docs/apache-airflow/stable/security/secrets/fernet.html#generating-fernet-key).

Then, check your settings for the OpenCVE webserver:

```
cat ../web/opencve/settings.py
```

You may want to customize the following fields:


```
SECRET_KEY = "..."

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "opencve",
        "USER": "opencve",
        "PASSWORD": "opencve",
        "HOST": "postgres",
        "PORT": "5432"
    }
}
```

You may need to change the email settings to use you own smtp relay, replace the lines:

```
# Email backend
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
```

By the following configuration:

```
# Email backend
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"

EMAIL_HOST = "smtp.example.com"
EMAIL_HOST_USER = "user"
EMAIL_HOST_PASSWORD = "password"
EMAIL_PORT = 587
EMAIL_USE_TLS = True

DEFAULT_FROM_EMAIL = "OpenCVE.dev <no-reply@example.com>"
```

Then, check the airflow configuration file:

```
cat /home/airflow/airflow.cfg
```

You may want to customize:

```
# The base URL of the OpenCVE webserver
web_base_url = <your_listening_ip or fqdn>

# The SMTP server used to send the email notifications
notification_smtp_host = smtp.example.com
notification_smtp_user = user
notification_smtp_password = password
notification_smtp_mail_from = john@example.com
notification_smtp_port = 587
notification_smtp_use_tls = True
notification_smtp_validate_certs = True
notification_smtp_timeout = 30
```

### Start the OpenCVE stack

Now you can run the command to bootstrap the entire stack:

```
./install.sh start-docker-stack
--> Starting Docker compose stack
[...]
```

You can check if the docker instances are running correctly:

```
docker ps
CONTAINER ID   IMAGE                       COMMAND                  CREATED         STATUS                   PORTS                    NAMES
c05be1dcd8a5   opencve-airflow-webserver   "/usr/bin/dumb-init …"   9 minutes ago   Up 7 minutes (healthy)   0.0.0.0:8080->8080/tcp   airflow-webserver
45dde77ffdd7   opencve-airflow-worker      "/usr/bin/dumb-init …"   9 minutes ago   Up 7 minutes (healthy)   8080/tcp                 airflow-worker
08302ce6d0f7   opencve-airflow-scheduler   "/usr/bin/dumb-init …"   9 minutes ago   Up 7 minutes (healthy)   8080/tcp                 airflow-scheduler
041ad3546c46   opencve-webserver           "python3 manage.py r…"   9 minutes ago   Up 9 minutes             8000/tcp                 webserver
5e0d20559b01   nginx:bookworm              "/docker-entrypoint.…"   9 minutes ago   Up 9 minutes             0.0.0.0:80->80/tcp       nginx
b91f0cda0c40   redis/redis-stack:latest    "/entrypoint.sh"         9 minutes ago   Up 9 minutes (healthy)   6379/tcp, 8001/tcp       redis
2be9eeed7d6c   postgres:15                 "docker-entrypoint.s…"   9 minutes ago   Up 9 minutes (healthy)   5432/tcp                 postgres
```

### Create privileged user

Create the super user for the OpenCVE web portal:

```
./install.sh create-superuser
--> Creating superuser on OpenCVE
Username: xxx
Email address: xxx
Password:
Password (again):
Superuser created successfully.
```

### Import OpenCVE Knowledge Base

We are good to import the OpenCVE KB:

```
./install.sh import-opencve-kb
--> Importing OpenCVE KB inside the database, this can take 15 to 30min.
Parsing the OpenCVE KB repository (/app/repositories/opencve-kb)
Found 240972 CVEs, adding them in database...
Done in 756.121s
```

You can now reach OpenCVE web portal at your configured IP/FQDN on the port 80 and the Airflow webserver on the port 8080.

