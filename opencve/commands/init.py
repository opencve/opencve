import os
import pathlib
import shutil

import click
from flask.cli import with_appcontext

from opencve.configuration import (
    DEFAULT_CONFIG,
    DEFAULT_WELCOME_FILES,
    OPENCVE_CONFIG,
    OPENCVE_HOME,
    OPENCVE_WELCOME_FILES,
)
from opencve.commands import info, error


def create_config():
    if not pathlib.Path(OPENCVE_CONFIG).exists():

        # Do not create the home if user directly specifies the config path
        if not os.environ.get("OPENCVE_CONFIG"):
            pathlib.Path(OPENCVE_HOME).mkdir(parents=True, exist_ok=True)

        with open(DEFAULT_CONFIG) as f:
            conf = f.read()

        # Generate a unique secret key
        conf = conf.replace("{SECRET_KEY}", os.urandom(32).hex())

        with open(OPENCVE_CONFIG, "w") as f:
            f.write(conf)

        # Copy the welcome files
        shutil.copytree(DEFAULT_WELCOME_FILES, OPENCVE_WELCOME_FILES)

        return OPENCVE_CONFIG, True

    return OPENCVE_CONFIG, False


@click.command()
@with_appcontext
def init():
    """Initialize the configuration file."""
    path, created = create_config()
    if created:
        info(f"Configuration created in {path}")
    else:
        error(f"Configuration already exists ({path})")
