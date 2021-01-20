import pytest
from flask import request

from opencve.models.users import User


@pytest.mark.parametrize(
    "first_name,last_name,email",
    [
        ("john", "doe", "john.doe@example.com"),
        ("john", "", "john.doe@example.com"),
        ("", "doe", "john.doe@example.com"),
        ("", "", "john.doe@example.com"),
        ("", "", "user@opencve.io"),
    ],
)
def test_edit_profile(login, client, first_name, last_name, email):
    user = User.query.first()
    assert user.first_name == ""
    assert user.last_name == ""
    assert user.email == "user@opencve.io"

    client.post(
        "/account/profile",
        data={"first_name": first_name, "last_name": last_name, "email": email},
        follow_redirects=True,
    )

    user = User.query.first()
    assert user.first_name == first_name
    assert user.last_name == last_name
    assert user.email == email


def test_edit_profile_email_required(login, client):
    response = client.post(
        "/account/profile", data={"email": ""}, follow_redirects=True
    )
    assert b"This field is required." in response.data


def test_edit_profile_with_existing_email(login, create_user, client):
    user = User.query.filter_by(username="user").first()
    assert user.email == "user@opencve.io"

    create_user("user2")

    response = client.post(
        "/account/profile", data={"email": "user2@opencve.io"}, follow_redirects=True
    )
    assert b"This Email is already in use. Please try another one" in response.data

    # Email has not changed
    user = User.query.filter_by(username="user").first()
    assert user.email == "user@opencve.io"
