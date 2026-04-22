from unittest.mock import MagicMock

import pytest
from bs4 import BeautifulSoup
from django.test import override_settings
from django.urls import reverse

from users.adapters import AccountAdapter, SocialAccountAdapter
from users.models import User


@pytest.mark.django_db
@override_settings(ENABLE_REGISTER=False)
def test_signup_get_is_closed_when_disabled(client):
    response = client.get(reverse("account_signup"))

    assert response.status_code == 200
    soup = BeautifulSoup(response.content, features="html.parser")
    assert soup.find("input", {"name": "username"}) is None
    assert soup.find("input", {"name": "password1"}) is None


@pytest.mark.django_db
@override_settings(ENABLE_REGISTER=False)
def test_signup_post_does_not_create_user_when_disabled(client):
    assert User.objects.filter(username="newuser").count() == 0

    response = client.post(
        reverse("account_signup"),
        data={
            "username": "newuser",
            "email": "newuser@example.com",
            "password1": "SuperSecret123!",
            "password2": "SuperSecret123!",
        },
    )

    assert response.status_code in (200, 302, 403)
    assert User.objects.filter(username="newuser").count() == 0


@pytest.mark.django_db
@override_settings(ENABLE_REGISTER=True)
def test_signup_get_is_open_by_default(client):
    response = client.get(reverse("account_signup"))

    assert response.status_code == 200
    soup = BeautifulSoup(response.content, features="html.parser")
    assert soup.find("input", {"name": "username"}) is not None
    assert soup.find("input", {"name": "password1"}) is not None


@pytest.mark.django_db
@override_settings(ENABLE_REGISTER=False)
def test_register_link_hidden_on_login_page_when_disabled(client):
    response = client.get(reverse("account_login"))

    assert response.status_code == 200
    assert reverse("account_signup").encode() not in response.content
    assert b"Register a new account?" not in response.content


@pytest.mark.django_db
@override_settings(ENABLE_REGISTER=True)
def test_register_link_visible_on_login_page_by_default(client):
    response = client.get(reverse("account_login"))

    assert response.status_code == 200
    assert reverse("account_signup").encode() in response.content
    assert b"Register a new account?" in response.content


@pytest.mark.django_db
@override_settings(ENABLE_REGISTER=False)
def test_register_link_hidden_on_base_nav_when_disabled(client):
    response = client.get(reverse("cves"))

    assert response.status_code == 200
    soup = BeautifulSoup(response.content, features="html.parser")
    signup_href = reverse("account_signup")
    assert not any(a.get("href") == signup_href for a in soup.find_all("a"))


@pytest.mark.django_db
@override_settings(ENABLE_REGISTER=True)
def test_register_link_visible_on_base_nav_by_default(client):
    response = client.get(reverse("cves"))

    assert response.status_code == 200
    soup = BeautifulSoup(response.content, features="html.parser")
    signup_href = reverse("account_signup")
    assert any(a.get("href") == signup_href for a in soup.find_all("a"))


@override_settings(ENABLE_REGISTER=False)
def test_account_adapter_is_closed_for_signup_when_disabled():
    adapter = AccountAdapter()
    assert adapter.is_open_for_signup(request=None) is False


@override_settings(ENABLE_REGISTER=True)
def test_account_adapter_is_open_for_signup_by_default():
    adapter = AccountAdapter()
    assert adapter.is_open_for_signup(request=None) is True


@override_settings(ENABLE_REGISTER=False)
def test_social_adapter_is_closed_for_signup_when_disabled():
    adapter = SocialAccountAdapter()
    assert adapter.is_open_for_signup(request=None, sociallogin=MagicMock()) is False


@override_settings(ENABLE_REGISTER=True)
def test_social_adapter_is_open_for_signup_by_default():
    adapter = SocialAccountAdapter()
    assert adapter.is_open_for_signup(request=None, sociallogin=MagicMock()) is True
