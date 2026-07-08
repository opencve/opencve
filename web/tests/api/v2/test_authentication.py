import pytest

from tests.api.v1.conftest import basic_auth_header
from tests.api.v2.conftest import bearer, org_list_url
from tests.conftest import TEST_PASSWORD


@pytest.mark.django_db
def test_unauthenticated_v2_endpoint_returns_401(client):
    """Reject unauthenticated requests to v2 endpoints."""
    response = client.get(org_list_url())

    assert response.status_code == 401


@pytest.mark.django_db
def test_basic_auth_on_v2_returns_401(client, api_context):
    """Reject Basic authentication on v2 endpoints."""
    user, _organization, _create_token = api_context

    response = client.get(org_list_url(), HTTP_AUTHORIZATION=basic_auth_header(user))

    assert response.status_code == 401


@pytest.mark.django_db
def test_session_auth_on_v2_returns_401(client, api_context):
    """Reject session authentication on v2 endpoints."""
    user, _organization, _create_token = api_context
    client.login(username=user.username, password=TEST_PASSWORD)

    response = client.get(org_list_url())

    assert response.status_code == 401


@pytest.mark.django_db
def test_valid_bearer_token_grants_access_to_organization_list(client, write_token):
    """Allow v2 organization list access with a valid Bearer token."""
    response = client.get(org_list_url(), **bearer(write_token))

    assert response.status_code == 200
    assert response.json()["count"] == 1
    assert response.json()["results"][0]["name"] == "acme"
