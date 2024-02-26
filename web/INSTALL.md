# OpenCVE Webserver

The OpenCVE webserver uses Django to interact with the user.

## Installation

Use a virtualenv:

```
cd web
python3.11 -m venv venv && source venv/bin/activate && pip install pip --upgrade
pip install -r requirements.txt
```

Clone these repositories in a folder:

```
cd /home/opencve/
git clone https://github.com/opencve/opencve-kb.git
git clone https://github.com/opencve/opencve-nvd.git
git clone https://github.com/CVEProject/cvelistV5.git
```

The OpenCVE v2 webserver needs its own database with some extensions:

```
CREATE DATABASE opencve_web;
\c opencve_web
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
```

You can now copy the `settings.py.example` file:

```
cp opencve/settings.py.example opencve/settings.py
```

And customize it:

```
SECRET_KEY = "..."

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "opencve_web",
        "USER": "",
        "PASSWORD": "",
        "HOST": "127.0.0.1",
        "PORT": "5432"
    }
}

EMAIL_BACKEND = "..."

KB_REPO_PATH = "/home/opencve/opencve-kb"
NVD_REPO_PATH = "/home/opencve/opencve-nvd"
MITRE_REPO_PATH = "/home/opencve/cvelistV5"
```

Create the tables and your first user:

```
python manage.py migrate
python manage.py createsuperuser
```

Finally, you can populate the database:

```
python manage.py import_cve
```
