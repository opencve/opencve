import json
from unittest.mock import patch

import pytest
from django.utils.timezone import now

from organizations.models import Membership
from organizations.services.memberships import invite_member
from tests.api.v2.conftest import (
    assert_v2_error,
    bearer,
    member_detail_url,
    members_url,
    write_token,
)


@pytest.mark.django_db
def test_list_members(client, write_token, api_context):
    """List returns organization memberships."""
    user, _organization, _create_token = api_context

    response = client.get(members_url(), **bearer(write_token))

    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 1
    assert data["results"][0]["email"] == user.email
    assert data["results"][0]["role"] == Membership.OWNER


@patch("organizations.services.memberships.send_organization_invitation_email")
@pytest.mark.django_db
def test_invite_existing_user(mock_send_invitation, client, write_token, create_user):
    """Invite an existing user and create a pending membership."""
    member = create_user(username="member", email="member@example.com")

    response = client.post(
        members_url(),
        data=json.dumps({"email": "member@example.com", "role": Membership.MEMBER}),
        content_type="application/json",
        **bearer(write_token),
    )

    assert response.status_code == 201
    data = response.json()
    assert data["email"] == member.email
    assert data["role"] == Membership.MEMBER
    assert data["is_invited"] is True
    assert data["date_joined"] is None
    mock_send_invitation.assert_called_once()


@patch("organizations.services.memberships.send_organization_signup_invitation_email")
@pytest.mark.django_db
def test_invite_unknown_email_pending(mock_send_signup_invitation, client, write_token):
    """Invite an unknown email and create a pending invitation."""
    response = client.post(
        members_url(),
        data=json.dumps({"email": "newuser@example.com", "role": Membership.MEMBER}),
        content_type="application/json",
        **bearer(write_token),
    )

    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "newuser@example.com"
    assert data["role"] == Membership.MEMBER
    assert data["is_invited"] is True
    assert data["date_joined"] is None
    mock_send_signup_invitation.assert_called_once()


@patch("organizations.services.memberships.send_organization_invitation_email")
@pytest.mark.django_db
def test_invite_duplicate_member(
    mock_send_invitation, client, write_token, create_user, api_context
):
    """Reject inviting a user who is already a member."""
    _user, organization, _create_token = api_context
    member = create_user(username="member", email="member@example.com")
    Membership.objects.create(
        user=member,
        organization=organization,
        role=Membership.MEMBER,
        date_joined=now(),
    )

    response = client.post(
        members_url(),
        data=json.dumps({"email": "member@example.com", "role": Membership.MEMBER}),
        content_type="application/json",
        **bearer(write_token),
    )

    assert_v2_error(
        response,
        "validation_error",
        details={"email": "Member already exist"},
    )
    mock_send_invitation.assert_not_called()


@patch("organizations.services.memberships.send_organization_signup_invitation_email")
@pytest.mark.django_db
def test_invite_duplicate_pending_invite(
    mock_send_signup_invitation, client, write_token, api_context
):
    """Reject a second invitation to the same pending email."""
    _user, organization, _create_token = api_context
    Membership.objects.create(
        user=None,
        email="newuser@example.com",
        organization=organization,
        role=Membership.MEMBER,
    )

    response = client.post(
        members_url(),
        data=json.dumps({"email": "newuser@example.com", "role": Membership.MEMBER}),
        content_type="application/json",
        **bearer(write_token),
    )

    assert_v2_error(
        response,
        "validation_error",
        details={"email": "An invitation has already been sent to this email address"},
    )
    mock_send_signup_invitation.assert_not_called()


@pytest.mark.django_db
def test_invite_invalid_role(client, write_token):
    """Reject member invite with an invalid role."""
    response = client.post(
        members_url(),
        data=json.dumps({"email": "newuser@example.com", "role": "admin"}),
        content_type="application/json",
        **bearer(write_token),
    )

    assert_v2_error(
        response,
        "validation_error",
        details={"role": ['"admin" is not a valid choice.']},
    )


@pytest.mark.django_db
def test_patch_last_owner_demotion(client, write_token, api_context):
    """Reject demoting the only active owner to member."""
    user, organization, _create_token = api_context
    membership = organization.membership_set.get(user=user)

    response = client.patch(
        member_detail_url(str(membership.id)),
        data=json.dumps({"role": Membership.MEMBER}),
        content_type="application/json",
        **bearer(write_token),
    )

    assert_v2_error(
        response,
        "validation_error",
        message="You cannot demote the only owner of the organization.",
    )


@pytest.mark.django_db
def test_patch_last_owner_demotion_with_pending_owner_invite(
    client, write_token, create_user, api_context
):
    """Reject demoting the only joined owner when a pending owner invite exists."""
    user, organization, _create_token = api_context
    membership = organization.membership_set.get(user=user)
    invited = create_user(username="invited", email="invited@example.com")
    Membership.objects.create(
        user=invited,
        organization=organization,
        role=Membership.OWNER,
        date_joined=None,
    )

    response = client.patch(
        member_detail_url(str(membership.id)),
        data=json.dumps({"role": Membership.MEMBER}),
        content_type="application/json",
        **bearer(write_token),
    )

    assert_v2_error(
        response,
        "validation_error",
        message="You cannot demote the only owner of the organization.",
    )


@pytest.mark.django_db
def test_patch_pending_invitation_role_change(
    client, write_token, create_user, api_context
):
    """Reject role change for a pending invitation."""
    _user, organization, _create_token = api_context
    member = create_user(username="member", email="member@example.com")
    membership = Membership.objects.create(
        user=member,
        organization=organization,
        role=Membership.MEMBER,
        date_joined=None,
    )

    response = client.patch(
        member_detail_url(str(membership.id)),
        data=json.dumps({"role": Membership.OWNER}),
        content_type="application/json",
        **bearer(write_token),
    )

    assert_v2_error(
        response,
        "validation_error",
        message="Cannot change role for pending invitations.",
    )


@pytest.mark.django_db
def test_patch_member_to_owner(client, write_token, create_user, api_context):
    """Promote an active member to owner."""
    _user, organization, _create_token = api_context
    member = create_user(username="member", email="member@example.com")
    membership = Membership.objects.create(
        user=member,
        organization=organization,
        role=Membership.MEMBER,
        date_joined=now(),
    )

    response = client.patch(
        member_detail_url(str(membership.id)),
        data=json.dumps({"role": Membership.OWNER}),
        content_type="application/json",
        **bearer(write_token),
    )

    assert response.status_code == 200
    assert response.json()["role"] == Membership.OWNER
    membership.refresh_from_db()
    assert membership.role == Membership.OWNER


@pytest.mark.django_db
def test_delete_member(client, write_token, create_user, api_context):
    """Delete a non-owner member successfully."""
    _user, organization, _create_token = api_context
    member = create_user(username="member", email="member@example.com")
    membership = Membership.objects.create(
        user=member,
        organization=organization,
        role=Membership.MEMBER,
        date_joined=now(),
    )

    response = client.delete(
        member_detail_url(str(membership.id)),
        **bearer(write_token),
    )

    assert response.status_code == 204
    assert not Membership.objects.filter(pk=membership.pk).exists()


@pytest.mark.django_db
def test_delete_last_owner(client, write_token, api_context):
    """Reject removing the last active owner."""
    user, organization, _create_token = api_context
    membership = organization.membership_set.get(user=user)

    response = client.delete(
        member_detail_url(str(membership.id)),
        **bearer(write_token),
    )

    assert_v2_error(
        response,
        "validation_error",
        message="Cannot remove the last owner.",
    )


@patch("organizations.services.memberships.send_organization_invitation_email")
@pytest.mark.django_db
def test_delete_pending_owner_invitation(
    mock_send_invitation, client, write_token, create_user, api_context
):
    """Allow deleting a pending owner invitation."""
    _user, organization, _create_token = api_context
    create_user(username="invited", email="invited@example.com")
    membership = invite_member(
        organization=organization,
        email="invited@example.com",
        role=Membership.OWNER,
    )

    response = client.delete(
        member_detail_url(str(membership.id)),
        **bearer(write_token),
    )

    assert response.status_code == 204
    assert not Membership.objects.filter(pk=membership.pk).exists()
    mock_send_invitation.assert_not_called()
