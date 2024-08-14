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
git clone https://github.com/CVEProject/cvelistV5.git
git clone https://github.com/opencve/opencve-nvd.git
git clone https://github.com/opencve/opencve-redhat.git
git clone https://github.com/cisagov/vulnrichment
```

You can now copy the example configuration files:

```
cp opencve/conf/.env.example opencve/conf/.env
cp opencve/conf/settings.py.example opencve/conf/settings.py
```

- the `.env` file contains the **required** settings you have to update in order to launch OpenCVE webserver. Note you can also use environment variables if you want.
- the `settings.py` file contains the **optional** settings. Unless you want to override other settings like the DEBUG mode or the API pagination, you can leave it as is.

The `OPENCVE_SECRET_KEY` variable of the `.env` file as to be replaced with a new secret:

```
python manage.py generate_secret_key
```

Create the tables and your first user:

```
python manage.py migrate
python manage.py createsuperuser
```

Finally, you can populate the database:

```
python manage.py import_cves
```

If you have an OpenCVE v1 instance, you can migrate the users and their subscriptions:

```
python manage.py import_from_v1
```
