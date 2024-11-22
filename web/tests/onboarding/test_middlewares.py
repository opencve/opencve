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
