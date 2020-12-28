import os

import click

from opencve import __version__
from opencve.commands.celery import celery
from opencve.commands.create_user import create_user
from opencve.commands.init import init
from opencve.commands.upgrade_db import upgrade_db
from opencve.commands.imports import import_data
from opencve.commands.webserver import webserver


@click.group()
@click.version_option(version=__version__)
def cli():
    """CVE Alerting Platform"""
    os.environ["FLASK_APP"] = "opencve.app:app"


cli.add_command(celery)
cli.add_command(create_user)
cli.add_command(import_data)
cli.add_command(init)
cli.add_command(upgrade_db)
cli.add_command(webserver)
