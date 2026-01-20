import base64

import pytest
from django.urls import reverse

from organizations.models import OrganizationAPIToken


@pytest.mark.django_db
def test_api_auth(client, create_user, create_organization):
    user = create_user(username="testuser")
    organization = create_organization(name="test-org", user=user)
    token_string = OrganizationAPIToken.create_token(
        organization=organization,
        name="API Token",
        description=None,
        created_by=user,
    )

    # Test 1: Unauthenticated request should fail
    response = client.get(reverse("organization-list"))
    assert response.status_code == 401

    # Test 2: Basic Authentication with user credentials
    credentials = base64.b64encode(f"{user.username}:password".encode()).decode()
    response = client.get(
        reverse("organization-list"),
        HTTP_AUTHORIZATION=f"Basic {credentials}",
    )
    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 1
    assert data["results"][0]["name"] == "test-org"

    # Test 3: Organization token authentication
    response = client.get(
        reverse("organization-list"),
        HTTP_AUTHORIZATION=f"Bearer {token_string}",
    )
    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 1
    assert data["results"][0]["name"] == "test-org"

    # Test 4: Invalid Basic Auth credentials should fail
    invalid_credentials = base64.b64encode("wronguser:wrongpass".encode()).decode()
    response = client.get(
        reverse("organization-list"),
        HTTP_AUTHORIZATION=f"Basic {invalid_credentials}",
    )
    assert response.status_code == 401

    # Test 5: Both authentication methods should work on the same endpoint
    # Basic Auth
    response = client.get(
        reverse("organization-detail", kwargs={"name": "test-org"}),
        HTTP_AUTHORIZATION=f"Basic {credentials}",
    )
    assert response.status_code == 200
    assert response.json()["name"] == "test-org"

    # Token Auth
    response = client.get(
        reverse("organization-detail", kwargs={"name": "test-org"}),
        HTTP_AUTHORIZATION=f"Bearer {token_string}",
    )
    assert response.status_code == 200
    assert response.json()["name"] == "test-org"


@pytest.mark.django_db
def test_api_auth_last_used_at(client, create_user, create_organization, create_cve):
    user = create_user()
    organization = create_organization(name="test-org", user=user)
    token_string = OrganizationAPIToken.create_token(
        organization=organization,
        name="API Token",
        description=None,
        created_by=user,
    )

    # Token has not been used yet
    parts = token_string.split(".", 2)
    token = OrganizationAPIToken.objects.get(token_id=parts[1])
    assert token.last_used_at is None

    # Make API request with token
    response = client.get(
        reverse("organization-list"),
        HTTP_AUTHORIZATION=f"Bearer {token_string}",
    )

    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 1
    assert data["results"][0]["name"] == "test-org"

    # Verify last_used_at was updated
    token = OrganizationAPIToken.objects.get(token_id=parts[1])
    assert token.last_used_at is not None


@pytest.mark.django_db
def test_api_auth_with_revoked_token(client, create_user, create_organization):
    user = create_user()
    organization = create_organization(name="test-org", user=user)

    token_string = OrganizationAPIToken.create_token(
        organization=organization,
        name="API Token",
        description=None,
        created_by=user,
    )

    # Revoke token
    parts = token_string.split(".", 2)
    token = OrganizationAPIToken.objects.get(token_id=parts[1])
    token.revoke()

    # Try to use revoked token
    response = client.get(
        reverse("organization-list"),
        HTTP_AUTHORIZATION=f"Bearer {token_string}",
    )

    assert response.status_code == 401


@pytest.mark.django_db
def test_api_auth_access_by_different_user(client, create_user, create_organization):
    user = create_user()
    organization = create_organization(name="test-org", user=user)
    token_string = OrganizationAPIToken.create_token(
        organization=organization,
        name="API Token",
        description=None,
        created_by=user,
    )

    # Can access own organization
    response = client.get(
        reverse("organization-detail", kwargs={"name": "test-org"}),
        HTTP_AUTHORIZATION=f"Bearer {token_string}",
    )
    assert response.status_code == 200
    assert response.json()["name"] == "test-org"

    # Cannot access other organizations
    user2 = create_user(username="user2")
    org2 = create_organization(name="other-org", user=user2)

    response = client.get(
        reverse("organization-detail", kwargs={"name": "other-org"}),
        HTTP_AUTHORIZATION=f"Bearer {token_string}",
    )
    assert response.status_code == 404


@pytest.mark.django_db
def test_api_auth_with_wrong_prefix(client, create_user, create_organization):
    """Test that a token with wrong prefix fails authentication."""
    user = create_user()
    organization = create_organization(name="test-org", user=user)
    token_string = OrganizationAPIToken.create_token(
        organization=organization,
        name="API Token",
        description=None,
        created_by=user,
    )

    # Extract token_id and secret from valid token
    parts = token_string.split(".", 2)
    token_id = parts[1]
    secret = parts[2]

    # Try with wrong prefix
    wrong_token = f"wrong_prefix.{token_id}.{secret}"
    response = client.get(
        reverse("organization-list"),
        HTTP_AUTHORIZATION=f"Bearer {wrong_token}",
    )
    assert response.status_code == 401


@pytest.mark.django_db
def test_api_auth_with_nonexistent_token_id(client, create_user, create_organization):
    """Test that a token with nonexistent token_id fails authentication."""
    user = create_user()
    organization = create_organization(name="test-org", user=user)
    token_string = OrganizationAPIToken.create_token(
        organization=organization,
        name="API Token",
        description=None,
        created_by=user,
    )

    # Extract secret from valid token
    parts = token_string.split(".", 2)
    secret = parts[2]

    # Try with nonexistent token_id
    nonexistent_token = f"{OrganizationAPIToken.TOKEN_PREFIX}.nonexistent123.{secret}"
    response = client.get(
        reverse("organization-list"),
        HTTP_AUTHORIZATION=f"Bearer {nonexistent_token}",
    )
    assert response.status_code == 401


@pytest.mark.django_db
def test_api_auth_with_inactive_token(client, create_user, create_organization):
    """Test that an inactive token fails authentication."""
    user = create_user()
    organization = create_organization(name="test-org", user=user)
    token_string = OrganizationAPIToken.create_token(
        organization=organization,
        name="API Token",
        description=None,
        created_by=user,
    )

    # Deactivate token
    parts = token_string.split(".", 2)
    token = OrganizationAPIToken.objects.get(token_id=parts[1])
    token.is_active = False
    token.save(update_fields=["is_active", "updated_at"])

    # Try to use inactive token
    response = client.get(
        reverse("organization-list"),
        HTTP_AUTHORIZATION=f"Bearer {token_string}",
    )
    assert response.status_code == 401
