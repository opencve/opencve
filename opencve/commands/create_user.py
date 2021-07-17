import datetime

import click
from flask import current_app as app
from flask.cli import with_appcontext
from sqlalchemy.exc import IntegrityError

from opencve.commands import ensure_config, error, info
from opencve.extensions import db
from opencve.models.users import User


@click.command()
@click.argument("username")
@click.argument("email")
@click.password_option()
@click.option("--admin", is_flag=True, help="Grant user as admin.")
@ensure_config
@with_appcontext
def create_user(username, email, password, admin):
    """Create a user or admin."""
    if User.query.filter_by(username=username).first():
        raise click.BadParameter(f"{username} already exists.", param_hint="username")
    if User.query.filter_by(email=email).first():
        raise click.BadParameter(f"{email} already exists.", param_hint="email")

    user = User(
        username=username,
        email=email,
        active=True,
        admin=admin,
        email_confirmed_at=datetime.datetime.utcnow(),
        password=app.user_manager.hash_password(password),
    )
    db.session.add(user)

    try:
        db.session.commit()
    except IntegrityError as e:
        error(e)
    else:
        info("User {} created.".format(username))
