import os

import click
from flask.cli import with_appcontext

from opencve.commands import ensure_config


@click.command(context_settings=dict(ignore_unknown_options=True))
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
@ensure_config
@with_appcontext
def webserver(args):
    """Run the webserver."""
    args = ["gunicorn"] + list(args)
    args.append("opencve.app:app")
    os.execvp(args[0], args)
