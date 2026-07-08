from unittest.mock import patch

import pytest
from django.utils.timezone import now
from rest_framework.exceptions import ValidationError

from organizations.models import Membership
from organizations.services.memberships import (
    generate_invitation_key,
    invite_member,
    remove_member,
    update_member_role,
    validate_member_removal,
    validate_member_role_update,
)


@pytest.mark.django_db
def test_generate_invitation_key_is_lowercase():
    """Invitation keys must be lowercase to match acceptance lookup."""
    for _ in range(20):
        key = generate_invitation_key()
        assert key == key.lower()
        assert len(key) == 64


@patch("organizations.services.memberships.send_organization_invitation_email")
@pytest.mark.django_db
def test_invite_member_existing_user(
    mock_send_invitation, create_user, create_organization
):
    """Invite an existing user and create a pending membership."""
    owner = create_user(username="owner", email="owner@example.com")
    organization = create_organization(name="acme", user=owner)
    member = create_user(username="member", email="member@example.com")

    membership = invite_member(
        organization=organization,
        email="member@example.com",
        role=Membership.MEMBER,
        request=object(),
    )

    assert membership.user == member
    assert membership.organization == organization
    assert membership.role == Membership.MEMBER
    assert membership.key is not None
    mock_send_invitation.assert_called_once()


@patch("organizations.services.memberships.send_organization_signup_invitation_email")
@pytest.mark.django_db
def test_invite_member_email_only_pending(
    mock_send_signup_invitation, create_user, create_organization
):
    """Invite a non-existing user with email-only pending membership."""
    owner = create_user(username="owner", email="owner@example.com")
    organization = create_organization(name="acme", user=owner)

    membership = invite_member(
        organization=organization,
        email="newuser@example.com",
        role=Membership.MEMBER,
        request=object(),
    )

    assert membership.user is None
    assert membership.email == "newuser@example.com"
    assert membership.organization == organization
    mock_send_signup_invitation.assert_called_once()


@patch("organizations.services.memberships.send_organization_invitation_email")
@pytest.mark.django_db
def test_invite_member_duplicate_member(
    mock_send_invitation, create_user, create_organization
):
    """Reject inviting a user who is already a member."""
    owner = create_user(username="owner", email="owner@example.com")
    organization = create_organization(name="acme", user=owner)
    member = create_user(username="member", email="member@example.com")
    Membership.objects.create(
        user=member,
        organization=organization,
        role=Membership.MEMBER,
        date_joined=now(),
    )

    with pytest.raises(ValidationError) as exc:
        invite_member(
            organization=organization,
            email="member@example.com",
            role=Membership.MEMBER,
        )

    assert exc.value.detail["email"] == "Member already exist"
    mock_send_invitation.assert_not_called()


@patch("organizations.services.memberships.send_organization_signup_invitation_email")
@pytest.mark.django_db
def test_invite_member_duplicate_pending_invite(
    mock_send_signup_invitation, create_user, create_organization
):
    """Reject a second invitation to the same pending email."""
    owner = create_user(username="owner", email="owner@example.com")
    organization = create_organization(name="acme", user=owner)
    Membership.objects.create(
        user=None,
        email="newuser@example.com",
        organization=organization,
        role=Membership.MEMBER,
    )

    with pytest.raises(ValidationError) as exc:
        invite_member(
            organization=organization,
            email="newuser@example.com",
            role=Membership.MEMBER,
        )

    assert (
        exc.value.detail["email"]
        == "An invitation has already been sent to this email address"
    )
    mock_send_signup_invitation.assert_not_called()


@patch("organizations.services.memberships.send_organization_signup_invitation_email")
@pytest.mark.django_db
def test_invite_member_email_normalization(
    mock_send_signup_invitation, create_user, create_organization
):
    """Normalize email casing and surrounding whitespace on invite."""
    owner = create_user(username="owner", email="owner@example.com")
    organization = create_organization(name="acme", user=owner)

    membership = invite_member(
        organization=organization,
        email="  John.Doe@Example.COM  ",
        role=Membership.MEMBER,
    )

    assert membership.email == "john.doe@example.com"
    mock_send_signup_invitation.assert_not_called()


@pytest.mark.django_db
def test_validate_member_role_update_empty_role(create_user, create_organization):
    """Reject role update when role is empty."""
    owner = create_user(username="owner")
    organization = create_organization(name="acme", user=owner)
    membership = organization.membership_set.get(user=owner)

    with pytest.raises(ValidationError, match="Role is required."):
        validate_member_role_update(membership=membership, role="")


@pytest.mark.django_db
def test_validate_member_role_update_invalid_role(create_user, create_organization):
    """Reject role update with an invalid role value."""
    owner = create_user(username="owner")
    organization = create_organization(name="acme", user=owner)
    membership = organization.membership_set.get(user=owner)

    with pytest.raises(ValidationError, match="Invalid role."):
        validate_member_role_update(membership=membership, role="admin")


@pytest.mark.django_db
def test_validate_member_role_update_pending_invitation(
    create_user, create_organization
):
    """Reject role update for a pending invitation."""
    owner = create_user(username="owner")
    organization = create_organization(name="acme", user=owner)
    member = create_user(username="member", email="member@example.com")
    membership = Membership.objects.create(
        user=member,
        organization=organization,
        role=Membership.MEMBER,
        date_joined=None,
    )

    with pytest.raises(
        ValidationError, match="Cannot change role for pending invitations."
    ):
        validate_member_role_update(membership=membership, role=Membership.OWNER)


@pytest.mark.django_db
def test_validate_member_role_update_last_owner_demotion(
    create_user, create_organization
):
    """Reject demoting the only active owner to member."""
    owner = create_user(username="owner")
    organization = create_organization(name="acme", user=owner)
    membership = organization.membership_set.get(user=owner)

    with pytest.raises(
        ValidationError, match="You cannot demote the only owner of the organization."
    ):
        validate_member_role_update(membership=membership, role=Membership.MEMBER)


@pytest.mark.django_db
def test_validate_member_role_update_last_owner_demotion_with_pending_owner_invite(
    create_user, create_organization
):
    """Reject demoting the only joined owner when a pending owner invite exists."""
    owner = create_user(username="owner")
    organization = create_organization(name="acme", user=owner)
    membership = organization.membership_set.get(user=owner)
    invited = create_user(username="invited", email="invited@example.com")
    Membership.objects.create(
        user=invited,
        organization=organization,
        role=Membership.OWNER,
        date_joined=None,
    )

    with pytest.raises(
        ValidationError, match="You cannot demote the only owner of the organization."
    ):
        validate_member_role_update(membership=membership, role=Membership.MEMBER)


@pytest.mark.django_db
def test_validate_member_removal_last_owner(create_user, create_organization):
    """Reject removing the last joined owner."""
    owner = create_user(username="owner")
    organization = create_organization(name="acme", user=owner)
    membership = organization.membership_set.get(user=owner)

    with pytest.raises(ValidationError, match="Cannot remove the last owner."):
        validate_member_removal(membership=membership)


@pytest.mark.django_db
def test_validate_member_removal_pending_owner_invitation(
    create_user, create_organization
):
    """Allow removing a pending owner invitation when one owner has joined."""
    owner = create_user(username="owner")
    organization = create_organization(name="acme", user=owner)
    invited = create_user(username="invited", email="invited@example.com")
    membership = Membership.objects.create(
        user=invited,
        organization=organization,
        role=Membership.OWNER,
        date_joined=None,
    )

    validate_member_removal(membership=membership)


@pytest.mark.django_db
def test_update_member_role_member_to_owner(create_user, create_organization):
    """Promote a member to owner when validation passes."""
    owner = create_user(username="owner")
    organization = create_organization(name="acme", user=owner)
    member = create_user(username="member", email="member@example.com")
    membership = Membership.objects.create(
        user=member,
        organization=organization,
        role=Membership.MEMBER,
        date_joined=now(),
    )

    updated = update_member_role(membership=membership, role=Membership.OWNER)

    updated.refresh_from_db()
    assert updated.role == Membership.OWNER


@pytest.mark.django_db
def test_remove_member_normal_delete(create_user, create_organization):
    """Delete a non-owner member successfully."""
    owner = create_user(username="owner")
    organization = create_organization(name="acme", user=owner)
    member = create_user(username="member", email="member@example.com")
    membership = Membership.objects.create(
        user=member,
        organization=organization,
        role=Membership.MEMBER,
        date_joined=now(),
    )

    remove_member(membership=membership)

    assert not Membership.objects.filter(pk=membership.pk).exists()


@pytest.mark.django_db
def test_remove_member_last_owner(create_user, create_organization):
    """Reject removing the last active owner."""
    owner = create_user(username="owner")
    organization = create_organization(name="acme", user=owner)
    membership = organization.membership_set.get(user=owner)

    with pytest.raises(ValidationError, match="Cannot remove the last owner."):
        remove_member(membership=membership)


@patch("organizations.services.memberships.send_organization_invitation_email")
@pytest.mark.django_db
def test_remove_member_pending_owner_invitation(
    mock_send_invitation, create_user, create_organization
):
    """Allow removing a pending owner invitation when one owner has joined."""
    owner = create_user(username="owner")
    organization = create_organization(name="acme", user=owner)
    invited_owner = create_user(username="invited", email="invited@example.com")
    membership = invite_member(
        organization=organization,
        email="invited@example.com",
        role=Membership.OWNER,
        request=object(),
    )

    remove_member(membership=membership)

    assert not Membership.objects.filter(pk=membership.pk).exists()
    assert Membership.objects.filter(user=invited_owner).exists() is False
    mock_send_invitation.assert_called_once()


@patch("organizations.services.memberships.send_organization_invitation_email")
@pytest.mark.django_db
def test_remove_member_pending_member_invitation(
    mock_send_invitation, create_user, create_organization
):
    """Allow removing a pending member invitation."""
    owner = create_user(username="owner")
    organization = create_organization(name="acme", user=owner)
    create_user(username="member", email="member@example.com")
    membership = invite_member(
        organization=organization,
        email="member@example.com",
        role=Membership.MEMBER,
        request=object(),
    )

    remove_member(membership=membership)

    assert not Membership.objects.filter(pk=membership.pk).exists()
    mock_send_invitation.assert_called_once()


@patch("organizations.services.memberships.send_organization_signup_invitation_email")
@pytest.mark.django_db
def test_remove_member_pending_signup_invitation(
    mock_send_signup_invitation, create_user, create_organization
):
    """Allow removing a pending signup invitation."""
    owner = create_user(username="owner")
    organization = create_organization(name="acme", user=owner)
    membership = invite_member(
        organization=organization,
        email="newuser@example.com",
        role=Membership.OWNER,
        request=object(),
    )

    remove_member(membership=membership)

    assert not Membership.objects.filter(pk=membership.pk).exists()
    mock_send_signup_invitation.assert_called_once()
