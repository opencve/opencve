import pytest
from django.urls import reverse

from organizations.models import OrganizationAPIToken


@pytest.mark.django_db
def test_revoked_token_returns_401(client, create_user, create_organization):
    """Reject API requests that use a revoked organization token."""
    user = create_user()
    organization = create_organization(name="test-org", user=user)
    token_string = OrganizationAPIToken.create_token(
        organization=organization,
        name="API Token",
        description=None,
        created_by=user,
    )

    parts = token_string.split(".", 2)
    token = OrganizationAPIToken.objects.get(token_id=parts[1])
    token.revoke()

    response = client.get(
        reverse("organization-list"),
        HTTP_AUTHORIZATION=f"Bearer {token_string}",
    )

    assert response.status_code == 401


@pytest.mark.django_db
def test_inactive_token_returns_401(client, create_user, create_organization):
    """Reject API requests that use a deactivated organization token."""
    user = create_user()
    organization = create_organization(name="test-org", user=user)
    token_string = OrganizationAPIToken.create_token(
        organization=organization,
        name="API Token",
        description=None,
        created_by=user,
    )

    parts = token_string.split(".", 2)
    token = OrganizationAPIToken.objects.get(token_id=parts[1])
    token.is_active = False
    token.save(update_fields=["is_active", "updated_at"])

    response = client.get(
        reverse("organization-list"),
        HTTP_AUTHORIZATION=f"Bearer {token_string}",
    )

    assert response.status_code == 401


@pytest.mark.django_db
def test_wrong_token_prefix_returns_401(client, create_user, create_organization):
    """Reject Bearer tokens that do not use the opc_org prefix."""
    user = create_user()
    organization = create_organization(name="test-org", user=user)
    token_string = OrganizationAPIToken.create_token(
        organization=organization,
        name="API Token",
        description=None,
        created_by=user,
    )

    parts = token_string.split(".", 2)
    wrong_token = f"wrong_prefix.{parts[1]}.{parts[2]}"

    response = client.get(
        reverse("organization-list"),
        HTTP_AUTHORIZATION=f"Bearer {wrong_token}",
    )

    assert response.status_code == 401


@pytest.mark.django_db
def test_nonexistent_token_id_returns_401(client, create_user, create_organization):
    """Reject Bearer tokens whose token_id does not exist in the database."""
    user = create_user()
    organization = create_organization(name="test-org", user=user)
    token_string = OrganizationAPIToken.create_token(
        organization=organization,
        name="API Token",
        description=None,
        created_by=user,
    )

    secret = token_string.split(".", 2)[2]
    nonexistent_token = f"{OrganizationAPIToken.TOKEN_PREFIX}.nonexistent123.{secret}"

    response = client.get(
        reverse("organization-list"),
        HTTP_AUTHORIZATION=f"Bearer {nonexistent_token}",
    )

    assert response.status_code == 401


@pytest.mark.django_db
def test_token_usage_updates_last_used_at(client, create_user, create_organization):
    """Update last_used_at when an organization token authenticates successfully."""
    user = create_user()
    organization = create_organization(name="test-org", user=user)
    token_string = OrganizationAPIToken.create_token(
        organization=organization,
        name="API Token",
        description=None,
        created_by=user,
    )

    parts = token_string.split(".", 2)
    token = OrganizationAPIToken.objects.get(token_id=parts[1])
    assert token.last_used_at is None

    response = client.get(
        reverse("organization-list"),
        HTTP_AUTHORIZATION=f"Bearer {token_string}",
    )

    assert response.status_code == 200
    token.refresh_from_db()
    assert token.last_used_at is not None
