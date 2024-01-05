## Requirements

Use a virtualenv (developed with Python 3.11):

```
cd web
python3 -m venv venv && source venv/bin/activate && pip install pip --upgrade
pip install -r requirements.txt
```

## Git

```
git clone https://github.com/CVEProject/cvelistV5.git
git clone https://github.com/opencve/nvd.git
```


## Database

```
CREATE DATABASE opencve_web;
\c opencve_web
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
```


## Django

### Configuration

Customize the `settings.py` file:

```
...
SECRET_KEY = "..."

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "opencvedb",
        "USER": "",
        "PASSWORD": "",
        "HOST": "127.0.0.1",
        "PORT": "5432"
    }
}

EMAIL_BACKEND = "..."

KB_REPO_PATH = "/Users/ncrocfer/Dev/opencve-project/opencve-kb"
MITRE_REPO_PATH = "/Users/ncrocfer/Dev/opencve-project/cvelistV5"
NVD_REPO_PATH = "/Users/ncrocfer/Dev/opencve-project/nvd"
...
```

Tables creation:

```
python manage.py migrate
```

First user:

```
python manage.py createsuperuser
```

Import list of CVEs (took between 10mn & 45mn on my laptop):

```
python manage.py import_cve
```

This command will give you to Airflow command used to import variables. Note them, we'll reuse it in the Airflow installation.
