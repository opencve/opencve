from datetime import date

import pytest
from django.contrib.auth.hashers import check_password
from django.core.exceptions import ValidationError
from django.utils.timezone import now
from freezegun import freeze_time

from organizations.models import Membership, Organization, OrganizationAPIToken


def test_organization_model(create_user, create_organization):
    user = create_user(username="user1")
    org = create_organization(name="organization1", user=user)

    assert org.name == "organization1"
    assert org.members.count() == 1
    assert org.members.first() == user
    assert org.membership_set.first().role == Membership.OWNER


def test_organization_get_projects_vendors(
    create_user, create_organization, create_project
):
    user = create_user()
    organization = create_organization("myorga", user)
    create_project(name="project1", organization=organization, vendors=["foo", "bar"])
    create_project(name="project2", organization=organization, vendors=["bar", "baz"])

    assert organization.get_projects_vendors() == ["bar", "baz", "foo"]


def test_organization_name_validator(create_organization):
    orga = Organization.objects.create(name="with'quote")
    with pytest.raises(ValidationError):
        assert orga.full_clean()


def test_membership_model(create_user):
    organization = Organization.objects.create(name="orga1")

    # Owner
    owner = create_user(username="user1")
    with freeze_time("2024-01-01"):
        membership = Membership.objects.create(
            user=owner,
            organization=organization,
            role=Membership.OWNER,
            date_invited=now(),
            date_joined=now(),
        )

    assert membership.user == owner
    assert membership.organization == organization
    assert membership.role == Membership.OWNER
    assert membership.date_invited.date() == date(2024, 1, 1)
    assert membership.date_joined.date() == date(2024, 1, 1)
    assert membership.key is None
    assert membership.is_owner is True
    assert membership.is_invited is False

    # Member
    member = create_user(username="user2")
    with freeze_time("2024-01-01"):
        membership = Membership.objects.create(
            user=member,
            organization=organization,
            role=Membership.MEMBER,
            date_invited=now(),
            key="foobar",
        )

    assert membership.user == member
    assert membership.organization == organization
    assert membership.role == Membership.MEMBER
    assert membership.date_invited.date() == date(2024, 1, 1)
    assert membership.date_joined is None
    assert membership.key == "foobar"
    assert membership.is_owner is False
    assert membership.is_invited is True


def test_organization_get_members(create_user, create_organization):
    """Test that get_members correctly filters and returns organization members."""
    organization = create_organization(name="orga1")
    other_organization = create_organization(name="orga2")

    # Create members
    active_user1 = create_user(username="alice")
    active_user2 = create_user(username="bob")
    invited_user = create_user(username="charlie")
    other_org_user = create_user(username="david")

    Membership.objects.create(
        user=active_user1,
        organization=organization,
        role=Membership.OWNER,
        date_invited=now(),
        date_joined=now(),
    )
    Membership.objects.create(
        user=active_user2,
        organization=organization,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )

    # Invited member (date_joined is None)
    Membership.objects.create(
        user=invited_user,
        organization=organization,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=None,
    )

    # Member of another organization (should not appear)
    Membership.objects.create(
        user=other_org_user,
        organization=other_organization,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )

    # Test with active=True (should return only active members)
    active_members = organization.get_members(active=True)
    assert list(active_members) == [active_user1, active_user2]
    assert invited_user not in active_members
    assert other_org_user not in active_members

    # Test with active=False (should return all members including invited
    all_members = organization.get_members(active=False)
    assert list(all_members) == [active_user1, active_user2, invited_user]
    assert other_org_user not in all_members

    # Test default behavior (active=True)
    default_members = organization.get_members()
    assert list(default_members) == [active_user1, active_user2]

    # Verify results are ordered by username
    usernames = [user.username for user in active_members]
    assert usernames == sorted(usernames)


@pytest.mark.django_db
def test_organization_api_token_create_token(create_user, create_organization):
    """Test that create_token generates a valid token."""
    user = create_user()
    organization = create_organization(name="test-org", user=user)
    token_string = OrganizationAPIToken.create_token(
        organization=organization,
        name="Test Token",
        description="Test description",
        created_by=user,
    )

    # Verify token format
    assert token_string.startswith("opc_org.")
    parts = token_string.split(".", 2)
    assert len(parts) == 3
    assert parts[0] == "opc_org"
    token_id = parts[1]
    secret = parts[2]

    # Verify token was created
    token = OrganizationAPIToken.objects.get(token_id=token_id)
    assert token.organization == organization
    assert token.name == "Test Token"
    assert token.description == "Test description"
    assert token.created_by == user
    assert token.is_active is True
    assert token.last_used_at is None

    # Verify secret hash
    assert check_password(secret, token.token_hash)


@pytest.mark.django_db
def test_organization_api_token_verify_token(create_user, create_organization):
    """Test that verify_token correctly validates secrets and rejects revoked tokens."""
    user = create_user()
    organization = create_organization(name="test-org", user=user)
    token_string = OrganizationAPIToken.create_token(
        organization=organization,
        name="Test Token",
        description=None,
        created_by=user,
    )

    parts = token_string.split(".", 2)
    token_id = parts[1]
    secret = parts[2]

    token = OrganizationAPIToken.objects.get(token_id=token_id)

    # Verify correct secret
    assert token.verify_token(secret) is True

    # Verify incorrect secret
    assert token.verify_token("wrong_secret") is False

    # Revoke and verify it fails
    token.revoke()
    assert token.verify_token(secret) is False


@pytest.mark.django_db
def test_organization_api_token_revoke_token(create_user, create_organization):
    """Test that revoke sets is_active to False."""
    user = create_user()
    organization = create_organization(name="test-org", user=user)

    token_string = OrganizationAPIToken.create_token(
        organization=organization,
        name="Test Token",
        description=None,
        created_by=user,
    )

    parts = token_string.split(".", 2)
    token_id = parts[1]

    token = OrganizationAPIToken.objects.get(token_id=token_id)
    assert token.is_active is True

    token.revoke()
    token.refresh_from_db()
    assert token.is_active is False


@pytest.mark.django_db
def test_organization_api_token_update_last_used(create_user, create_organization):
    """Test that update_last_used sets the last_used_at timestamp."""
    user = create_user()
    organization = create_organization(name="test-org", user=user)
    token_string = OrganizationAPIToken.create_token(
        organization=organization,
        name="Test Token",
        description=None,
        created_by=user,
    )

    parts = token_string.split(".", 2)
    token_id = parts[1]

    token = OrganizationAPIToken.objects.get(token_id=token_id)
    assert token.last_used_at is None

    token.update_last_used()
    token.refresh_from_db()
    assert token.last_used_at is not None
    assert token.last_used_at <= now()


@pytest.mark.django_db
def test_organization_api_token_unique_id(create_user, create_organization):
    """Test that each token has a unique token_id."""
    user = create_user()
    organization = create_organization(name="test-org", user=user)

    token1 = OrganizationAPIToken.create_token(
        organization=organization,
        name="Token 1",
        description=None,
        created_by=user,
    )

    token2 = OrganizationAPIToken.create_token(
        organization=organization,
        name="Token 2",
        description=None,
        created_by=user,
    )

    parts1 = token1.split(".", 2)
    parts2 = token2.split(".", 2)

    # Token IDs should be different
    assert parts1[1] != parts2[1]
