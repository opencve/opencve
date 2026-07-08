import pytest
from django.urls import reverse

from organizations.models import OrganizationAPIToken

from tests.api.v1.conftest import basic_auth_header


@pytest.mark.django_db
def test_unauthenticated_request_returns_401(client, create_user, create_organization):
    """Reject unauthenticated requests to the v1 organization list endpoint."""
    create_organization(name="test-org", user=create_user())

    response = client.get(reverse("organization-list"))

    assert response.status_code == 401


@pytest.mark.django_db
def test_basic_auth_grants_access(client, create_user, create_organization):
    """Allow v1 organization list access with valid Basic authentication."""
    user = create_user(username="testuser")
    organization = create_organization(name="test-org", user=user)

    response = client.get(
        reverse("organization-list"),
        HTTP_AUTHORIZATION=basic_auth_header(user),
    )

    assert response.status_code == 200
    assert response.json()["count"] == 1
    assert response.json()["results"][0]["name"] == "test-org"


@pytest.mark.django_db
def test_bearer_token_grants_access(client, create_user, create_organization):
    """Allow v1 organization list access with a valid organization Bearer token."""
    user = create_user()
    organization = create_organization(name="test-org", user=user)
    token_string = OrganizationAPIToken.create_token(
        organization=organization,
        name="API Token",
        description=None,
        created_by=user,
    )

    response = client.get(
        reverse("organization-list"),
        HTTP_AUTHORIZATION=f"Bearer {token_string}",
    )

    assert response.status_code == 200
    assert response.json()["count"] == 1
    assert response.json()["results"][0]["name"] == "test-org"


@pytest.mark.django_db
def test_invalid_basic_auth_returns_401(client):
    """Reject v1 requests with invalid Basic authentication credentials."""
    response = client.get(
        reverse("organization-list"),
        HTTP_AUTHORIZATION="Basic d3Jvbmd1c2VyOndyb25ncGFzcw==",
    )

    assert response.status_code == 401


@pytest.mark.django_db
def test_bearer_token_cannot_access_other_organization(
    client, create_user, create_organization
):
    """Return 404 when a token tries to access another organization's detail."""
    user = create_user()
    organization = create_organization(name="test-org", user=user)
    token_string = OrganizationAPIToken.create_token(
        organization=organization,
        name="API Token",
        description=None,
        created_by=user,
    )

    user2 = create_user(username="user2")
    create_organization(name="other-org", user=user2)

    response = client.get(
        reverse("organization-detail", kwargs={"name": "other-org"}),
        HTTP_AUTHORIZATION=f"Bearer {token_string}",
    )

    assert response.status_code == 404


@pytest.mark.django_db
def test_basic_and_bearer_auth_work_on_organization_detail(
    client, create_user, create_organization
):
    """Allow both Basic and Bearer authentication on the v1 organization detail."""
    user = create_user(username="testuser")
    organization = create_organization(name="test-org", user=user)
    token_string = OrganizationAPIToken.create_token(
        organization=organization,
        name="API Token",
        description=None,
        created_by=user,
    )

    basic_response = client.get(
        reverse("organization-detail", kwargs={"name": "test-org"}),
        HTTP_AUTHORIZATION=basic_auth_header(user),
    )
    bearer_response = client.get(
        reverse("organization-detail", kwargs={"name": "test-org"}),
        HTTP_AUTHORIZATION=f"Bearer {token_string}",
    )

    assert basic_response.status_code == 200
    assert bearer_response.status_code == 200
    assert basic_response.json()["name"] == "test-org"
    assert bearer_response.json()["name"] == "test-org"
