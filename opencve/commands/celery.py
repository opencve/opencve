import os

import click
from flask.cli import with_appcontext

from opencve.commands import ensure_config


@click.group()
def celery():
    """Run Celery commands."""


@celery.command(context_settings=dict(ignore_unknown_options=True))
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
@ensure_config
@with_appcontext
def worker(args):
    """Run a Celery worker."""
    args = "celery worker -A opencve.app:cel".split() + list(args)
    os.execvp(args[0], args)


@celery.command(context_settings=dict(ignore_unknown_options=True))
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
@ensure_config
@with_appcontext
def beat(args):
    """Start the Celery beat."""
    args = "celery beat -A opencve.app:cel".split() + list(args)
    os.execvp(args[0], args)
