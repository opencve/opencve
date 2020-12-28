from pathlib import Path

import click
from flask.cli import with_appcontext
from flask_migrate import upgrade

from opencve.commands import ensure_config


@click.command()
@ensure_config
@with_appcontext
def upgrade_db():
    """Create or upgrade the database."""
    migrations_path = Path(__file__).parent.parent.resolve() / "migrations"
    upgrade(directory=str(migrations_path))
