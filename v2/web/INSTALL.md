## Requirements

Use a virtualenv:

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
CREATE DATABASE opencvedb;
\c opencvedb
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
```


## Django

### Configuration

Copy the `settings.py` template:

```
cp opencve/settings.py.example opencve/settings.py
```

And customize its fields:

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

MITRE_REPO_PATH = "/Users/ncrocfer/Dev/cvelistV5"
NVD_REPO_PATH = "/Users/ncrocfer/Dev/nvd"
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
