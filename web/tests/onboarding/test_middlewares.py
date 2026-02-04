import pytest
from django.test import override_settings
from django.urls import reverse


@pytest.mark.django_db
def test_onboarding_middleware_with_unauthenticated_user(client):
    response = client.get(reverse("cves"))
    assert response.status_code == 200
    assert b"No CVE found." in response.content


def test_onboarding_middleware_no_organization(auth_client, create_user):
    user = create_user(username="john")
    client = auth_client(user)

    response = client.get(reverse("cves"), follow=True)
    assert response.status_code == 200
    assert response.redirect_chain == [(reverse("onboarding"), 302)]
    assert b"Welcome to OpenCVE john" in response.content


def test_organization_middleware_setting(auth_client, create_user):
    user = create_user(username="john")
    client = auth_client(user)

    response = client.get(reverse("cves"), follow=True)
    assert response.redirect_chain == [(reverse("onboarding"), 302)]
    assert b"Welcome to OpenCVE john" in response.content

    with override_settings(ENABLE_ONBOARDING=False):
        response = client.get(reverse("cves"))
    assert response.status_code == 200
    assert b"No CVE found." in response.content


def test_onboarding_middleware_user_with_organization_no_redirect(
    auth_client, create_user, create_organization
):
    """User with at least one organization is not redirected to onboarding."""
    user = create_user(username="john")
    create_organization("acme", user=user)
    client = auth_client(user)

    response = client.get(reverse("cves"))
    assert response.status_code == 200
    assert response.get("Location") != reverse("onboarding")
    assert b"No CVE found." in response.content


def test_onboarding_middleware_allowed_view_onboarding(auth_client, create_user):
    """User without organization can access the onboarding page without redirect."""
    user = create_user(username="john")
    client = auth_client(user)

    response = client.get(reverse("onboarding"))
    assert response.status_code == 200
    assert response.get("Location") is None
    assert b"Welcome to OpenCVE john" in response.content


def test_onboarding_middleware_allowed_view_search_vendors_products(
    auth_client, create_user
):
    """User without organization can access onboarding search endpoint without redirect."""
    user = create_user(username="john")
    client = auth_client(user)

    response = client.get(reverse("onboarding_search_vendors_products"))
    assert response.status_code == 200
    assert response.get("Location") is None


def test_onboarding_middleware_path_api_no_redirect(auth_client, create_user):
    """User without organization can access /api/ paths without redirect."""
    user = create_user(username="john")
    client = auth_client(user)

    response = client.get("/api/cve/")
    assert response.get("Location") != reverse("onboarding")


def test_onboarding_middleware_path_settings_no_redirect(auth_client, create_user):
    """User without organization can access /settings/ paths without redirect."""
    user = create_user(username="john")
    client = auth_client(user)

    response = client.get(reverse("settings_profile"))
    assert response.get("Location") != reverse("onboarding")


def test_onboarding_middleware_path_debug_no_redirect(auth_client, create_user):
    """User without organization can access /__debug__/ paths without redirect."""
    user = create_user(username="john")
    client = auth_client(user)

    response = client.get("/__debug__/")
    assert response.get("Location") != reverse("onboarding")
