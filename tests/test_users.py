import datetime

import pytest
from flask import request

from opencve.extensions import db
from opencve.models.users import User


def _create_user(app):
    user = User(
        username="user",
        email="user@opencve.io",
        active=True,
        admin=False,
        email_confirmed_at=datetime.datetime.utcnow(),
        password=app.user_manager.hash_password("password"),
    )
    db.session.add(user)
    db.session.commit()


def test_empty_login(app, client):
    with client:
        response = client.post(
            "/login", data=dict(username="", password=""), follow_redirects=True
        )
        assert request.path == "/login"
        assert b"Username is required" in response.data
        assert b"Password is required" in response.data


@pytest.mark.parametrize(
    "user,password",
    [
        ("user", "password"),
        ("user@opencve.io", "password"),
    ],
)
def test_login_success(app, client, user, password):
    _create_user(app)
    with client:
        response = client.post(
            "/login", data=dict(username=user, password=password), follow_redirects=True
        )

        assert request.path == "/"
        assert b"You have signed in successfully." in response.data


@pytest.mark.parametrize(
    "user,password",
    [
        ("user", "bad_password"),
        ("bad_user", "password"),
        ("bad_user", "bad_password"),
    ],
)
def test_login_errors(app, client, user, password):
    with client:
        response = client.post(
            "/login", data=dict(username=user, password=password), follow_redirects=True
        )
        assert request.path == "/login"
        assert response.data.count(b"Incorrect Username/Email and/or Password") == 2


def test_logout(app, client):
    _create_user(app)
    client.post(
        "/login", data=dict(username="user", password="password"), follow_redirects=True
    )

    with client:
        response = client.post("/logout", follow_redirects=True)
        assert request.path == "/login"
        assert b"You have signed out successfully." in response.data
