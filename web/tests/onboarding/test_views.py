import json
from datetime import date

import pytest
from bs4 import BeautifulSoup
from django.urls import reverse
from freezegun import freeze_time

from cves.constants import PRODUCT_SEPARATOR
from cves.models import Product, Vendor
from organizations.models import Membership, Organization
from projects.models import Notification, Project


def test_onboarding_dispatch(client, auth_client, create_user, create_organization):
    url = reverse("onboarding")

    # Unauthenticated user can not access the onboarding
    response = client.get(url, follow=True)
    assert response.redirect_chain == [
        (f"{reverse('account_login')}?next={reverse('onboarding')}", 302)
    ]

    # User without organization can access the onboarding
    user = create_user(username="john")
    client = auth_client(user)

    response = client.get(reverse("onboarding"))
    assert response.status_code == 200
    assert b"Welcome to OpenCVE john" in response.content

    # User with an organization is redirected to the homepage
    create_organization(name="orga", user=user)
    response = client.get(reverse("onboarding"), follow=True)
    assert response.redirect_chain == [(reverse("home"), 302)]


def test_onboarding_access_settings(auth_client, create_user):
    user = create_user(username="john")
    client = auth_client(user)

    response = client.get(reverse("cves"), follow=True)
    assert response.redirect_chain == [(reverse("onboarding"), 302)]

    response = client.get(reverse("account_logout"))
    assert response.status_code == 200


def test_onboarding_invalid_form(auth_client, create_user):
    user = create_user(username="john")
    client = auth_client(user)
    url = reverse("onboarding")

    response = client.post(url, data={}, follow=False)
    assert response.status_code == 200
    soup = BeautifulSoup(response.content, features="html.parser")
    # Errors are rendered in <p class="text-danger">
    assert "This field is required" in response.content.decode()


def test_onboarding_get_initial_notification_email_prefilled(auth_client, create_user):
    """get_initial() pre-fills notification_email with the current user's email."""
    user = create_user(username="john", email="john@example.com")
    client = auth_client(user)
    url = reverse("onboarding")

    response = client.get(url)
    assert response.status_code == 200
    soup = BeautifulSoup(response.content, features="html.parser")
    email_input = soup.find("input", {"name": "notification_email"})
    assert email_input is not None
    assert email_input.get("value") == "john@example.com"


@freeze_time("2024-01-01")
def test_onboarding_valid_form_minimal(auth_client, create_user):
    """Complete onboarding with only organization and project (no subscriptions, no notification)."""
    user = create_user(username="john", email="john@doe.com")
    client = auth_client(user)
    url = reverse("onboarding")

    response = client.post(
        url,
        data={
            "organization": "myorga",
            "project": "myproject",
            "selected_subscriptions": "[]",
            "enable_email_notification": "",
            "cvss31_min": "0",
        },
        follow=True,
    )
    assert response.redirect_chain == [(reverse("home"), 302)]

    soup = BeautifulSoup(response.content, features="html.parser")
    assert "Welcome to OpenCVE" in soup.find("div", {"class": "alert-success"}).text

    orga = Organization.objects.first()
    assert orga.name == "myorga"
    assert list(orga.members.all()) == [user]

    membership = Membership.objects.first()
    assert membership.user == user
    assert membership.organization == orga
    assert membership.role == Membership.OWNER
    assert membership.date_invited.date() == date(2024, 1, 1)
    assert membership.date_joined.date() == date(2024, 1, 1)
    assert not membership.key

    project = Project.objects.first()
    assert project.name == "myproject"
    assert project.organization == orga
    assert project.subscriptions == {"vendors": [], "products": []}

    assert Notification.objects.count() == 0


@freeze_time("2024-01-01")
def test_onboarding_valid_form_with_subscriptions(auth_client, create_user, db):
    """Onboarding with selected vendors/products."""
    vendor = Vendor.objects.create(name="python")
    Product.objects.create(name="django", vendor=vendor)

    user = create_user(username="john", email="john@doe.com")
    client = auth_client(user)
    url = reverse("onboarding")

    subscriptions = json.dumps(["python", f"python{PRODUCT_SEPARATOR}django"])
    response = client.post(
        url,
        data={
            "organization": "myorga",
            "project": "myproject",
            "selected_subscriptions": subscriptions,
            "enable_email_notification": "",
            "cvss31_min": "0",
        },
        follow=True,
    )
    assert response.redirect_chain == [(reverse("home"), 302)]

    project = Project.objects.first()
    assert project.subscriptions == {
        "vendors": ["python"],
        "products": [f"python{PRODUCT_SEPARATOR}django"],
    }


@freeze_time("2024-01-01")
def test_onboarding_form_valid_subscriptions_only_vendors(auth_client, create_user, db):
    """form_valid: selected_subscriptions with only vendor names → vendors list, empty products."""
    Vendor.objects.create(name="python")
    Vendor.objects.create(name="linux")
    user = create_user(username="john", email="john@doe.com")
    client = auth_client(user)
    url = reverse("onboarding")

    response = client.post(
        url,
        data={
            "organization": "myorga",
            "project": "myproject",
            "selected_subscriptions": json.dumps(["python", "linux"]),
            "enable_email_notification": "",
            "cvss31_min": "0",
        },
        follow=True,
    )
    assert response.redirect_chain == [(reverse("home"), 302)]

    project = Project.objects.first()
    assert project.subscriptions == {"vendors": ["python", "linux"], "products": []}


@freeze_time("2024-01-01")
def test_onboarding_form_valid_subscriptions_only_products(
    auth_client, create_user, db
):
    """form_valid: selected_subscriptions with only product keys → products list, empty vendors."""
    vendor = Vendor.objects.create(name="python")
    Product.objects.create(name="django", vendor=vendor)
    user = create_user(username="john", email="john@doe.com")
    client = auth_client(user)
    url = reverse("onboarding")

    response = client.post(
        url,
        data={
            "organization": "myorga",
            "project": "myproject",
            "selected_subscriptions": json.dumps([f"python{PRODUCT_SEPARATOR}django"]),
            "enable_email_notification": "",
            "cvss31_min": "0",
        },
        follow=True,
    )
    assert response.redirect_chain == [(reverse("home"), 302)]

    project = Project.objects.first()
    assert project.subscriptions == {
        "vendors": [],
        "products": [f"python{PRODUCT_SEPARATOR}django"],
    }


@freeze_time("2024-01-01")
def test_onboarding_form_valid_notification_linked_to_project(auth_client, create_user):
    """form_valid: when enable_email_notification is True, Notification is created and linked to project."""
    user = create_user(username="john", email="john@doe.com")
    client = auth_client(user)
    url = reverse("onboarding")

    response = client.post(
        url,
        data={
            "organization": "myorga",
            "project": "myproject",
            "selected_subscriptions": "[]",
            "enable_email_notification": "1",
            "notification_email": "alerts@example.com",
            "cvss31_min": "7",
        },
        follow=True,
    )
    assert response.redirect_chain == [(reverse("home"), 302)]

    project = Project.objects.first()
    notification = Notification.objects.first()
    assert notification is not None
    assert notification.project == project
    assert notification.configuration["extras"]["email"] == "alerts@example.com"
    assert notification.configuration["metrics"]["cvss31"] == "7"


@freeze_time("2024-01-01")
def test_onboarding_valid_form_with_notification(auth_client, create_user):
    """Onboarding with email notification enabled."""
    user = create_user(username="john", email="john@doe.com")
    client = auth_client(user)
    url = reverse("onboarding")

    response = client.post(
        url,
        data={
            "organization": "myorga",
            "project": "myproject",
            "selected_subscriptions": "[]",
            "enable_email_notification": "1",
            "notification_email": "alerts@example.com",
            "cvss31_min": "7",
        },
        follow=True,
    )
    assert response.redirect_chain == [(reverse("home"), 302)]

    notification = Notification.objects.first()
    assert notification is not None
    assert notification.name == "Email notifications"
    assert notification.type == "email"
    assert notification.is_enabled is True
    assert notification.configuration == {
        "types": ["created", "first_time"],
        "extras": {"email": "alerts@example.com"},
        "metrics": {"cvss31": "7"},
    }


@pytest.mark.django_db
def test_onboarding_search_requires_auth(client):
    """Search endpoint requires authenticated user."""
    url = reverse("onboarding_search_vendors_products")
    response = client.get(url, {"q": "test"}, follow=True)
    assert response.redirect_chain
    assert "login" in response.redirect_chain[0][0]


# --- OnboardingMixin (via SearchVendorsProductsView) ---


def test_search_vendors_products_redirect_when_user_has_organization(
    auth_client, create_user, create_organization
):
    """OnboardingMixin: user with current_organization is redirected to home."""
    user = create_user(username="john")
    create_organization("acme", user=user)
    client = auth_client(user)
    url = reverse("onboarding_search_vendors_products")

    response = client.get(url, {"q": "test"}, follow=True)
    assert response.redirect_chain == [(reverse("home"), 302)]


# --- SearchVendorsProductsView ---


def test_search_vendors_products_empty_q_returns_empty_lists(auth_client, create_user):
    """Search with empty or missing q returns empty vendors and products."""
    user = create_user(username="john")
    client = auth_client(user)
    url = reverse("onboarding_search_vendors_products")

    for params in [{"q": ""}, {"q": "   "}, {}]:
        response = client.get(url, params)
        assert response.status_code == 200
        data = response.json()
        assert data == {"vendors": [], "products": []}


def test_search_vendors_products_case_insensitive(auth_client, create_user, db):
    """Search is case-insensitive (q is lowercased)."""
    Vendor.objects.create(name="python")
    user = create_user(username="john")
    client = auth_client(user)
    url = reverse("onboarding_search_vendors_products")

    response = client.get(url, {"q": "PY"})
    assert response.status_code == 200
    data = response.json()
    assert data == {
        "products": [],
        "vendors": [{"human_name": "Python", "name": "python"}],
    }


def test_search_vendors_products_includes_products_by_vendor_name(
    auth_client, create_user, db
):
    """Vendor matching q is returned; product name also matching q is in products."""
    vendor = Vendor.objects.create(name="djangoproject")
    Product.objects.create(name="django", vendor=vendor)
    user = create_user(username="john")
    client = auth_client(user)
    url = reverse("onboarding_search_vendors_products")

    response = client.get(url, {"q": "django"})
    assert response.status_code == 200
    data = response.json()
    assert data == {
        "vendors": [{"name": "djangoproject", "human_name": "Djangoproject"}],
        "products": [
            {
                "name": "django",
                "vendor": "djangoproject",
                "vendored_name": "djangoproject$PRODUCT$django",
                "human_name": "Django",
            }
        ],
    }
