import json
from unittest.mock import patch

import pytest
from django.test import override_settings
from django.utils.timezone import now

from organizations.models import Membership, OrganizationAPIToken
from organizations.services.memberships import invite_member
from projects.models import ProjectMembership
from tests.api.v2.conftest import (
    assert_v2_error,
    bearer,
    member_detail_url,
    members_url,
    project_member_detail_url,
    project_members_url,
    read_token,
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
        data=json.dumps({"email": "newuser@example.com", "role": "superuser"}),
        content_type="application/json",
        **bearer(write_token),
    )

    assert_v2_error(
        response,
        "validation_error",
        details={"role": ['"superuser" is not a valid choice.']},
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


@pytest.mark.django_db
def test_list_project_members_empty(client, api_context, write_token, create_project):
    """List returns an empty page when the project has no explicit members."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)

    response = client.get(project_members_url(), **bearer(write_token))

    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 0
    assert data["results"] == []


@pytest.mark.django_db
def test_list_project_members_returns_assignments(
    client, api_context, write_token, create_project, create_user
):
    """List returns project memberships with membership_id and user fields."""
    _user, organization, _create_token = api_context
    project = create_project(name="prod", organization=organization)
    member = create_user(username="member", email="member@example.com")
    org_membership = Membership.objects.create(
        user=member,
        organization=organization,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    ProjectMembership.objects.create(
        project=project,
        membership=org_membership,
        role=ProjectMembership.CONTRIBUTOR,
    )

    response = client.get(project_members_url(), **bearer(write_token))

    assert response.status_code == 200
    results = response.json()["results"]
    assert len(results) == 1
    assert results[0]["role"] == ProjectMembership.CONTRIBUTOR
    assert results[0]["membership_id"] == org_membership.pk
    assert results[0]["email"] == "member@example.com"
    assert results[0]["username"] == "member"


@pytest.mark.django_db
def test_add_project_member_success(
    client, api_context, write_token, create_project, create_user
):
    """POST adds a joined organization member to the project."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)
    member = create_user(username="member", email="member@example.com")
    org_membership = Membership.objects.create(
        user=member,
        organization=organization,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )

    response = client.post(
        project_members_url(),
        data=json.dumps(
            {
                "membership_id": org_membership.pk,
                "role": ProjectMembership.CONTRIBUTOR,
            }
        ),
        content_type="application/json",
        **bearer(write_token),
    )

    assert response.status_code == 201
    data = response.json()
    assert data["role"] == ProjectMembership.CONTRIBUTOR
    assert data["membership_id"] == org_membership.pk
    assert ProjectMembership.objects.filter(
        project__name="prod",
        membership=org_membership,
        role=ProjectMembership.CONTRIBUTOR,
    ).exists()


@pytest.mark.django_db
def test_patch_project_member_role(
    client, api_context, write_token, create_project, create_user
):
    """PATCH updates the project role of an assigned member."""
    _user, organization, _create_token = api_context
    project = create_project(name="prod", organization=organization)
    member = create_user(username="member", email="member@example.com")
    org_membership = Membership.objects.create(
        user=member,
        organization=organization,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    project_membership = ProjectMembership.objects.create(
        project=project,
        membership=org_membership,
        role=ProjectMembership.VIEWER,
    )

    response = client.patch(
        project_member_detail_url(project_membership.pk),
        data=json.dumps({"role": ProjectMembership.PROJECT_ADMIN}),
        content_type="application/json",
        **bearer(write_token),
    )

    assert response.status_code == 200
    assert response.json()["role"] == ProjectMembership.PROJECT_ADMIN
    project_membership.refresh_from_db()
    assert project_membership.role == ProjectMembership.PROJECT_ADMIN


@pytest.mark.django_db
def test_delete_project_member(
    client, api_context, write_token, create_project, create_user
):
    """DELETE removes a member from the project without deleting org membership."""
    _user, organization, _create_token = api_context
    project = create_project(name="prod", organization=organization)
    member = create_user(username="member", email="member@example.com")
    org_membership = Membership.objects.create(
        user=member,
        organization=organization,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    project_membership = ProjectMembership.objects.create(
        project=project,
        membership=org_membership,
        role=ProjectMembership.VIEWER,
    )

    response = client.delete(
        project_member_detail_url(project_membership.pk),
        **bearer(write_token),
    )

    assert response.status_code == 204
    assert not ProjectMembership.objects.filter(pk=project_membership.pk).exists()
    assert Membership.objects.filter(pk=org_membership.pk).exists()


@pytest.mark.django_db
def test_add_project_member_pending_org_invitation(
    client, api_context, write_token, create_project, create_user
):
    """Reject adding a user who has not accepted the organization invitation yet."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)
    member = create_user(username="member", email="member@example.com")
    pending = Membership.objects.create(
        user=member,
        organization=organization,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=None,
    )

    response = client.post(
        project_members_url(),
        data=json.dumps(
            {
                "membership_id": pending.pk,
                "role": ProjectMembership.CONTRIBUTOR,
            }
        ),
        content_type="application/json",
        **bearer(write_token),
    )

    assert_v2_error(
        response,
        "validation_error",
        details={
            "membership_id": "Member has not joined the organization yet.",
        },
    )


@pytest.mark.django_db
def test_add_project_member_unknown_membership_id(
    client, api_context, write_token, create_project
):
    """Return 404 when membership_id does not exist in the organization."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)

    response = client.post(
        project_members_url(),
        data=json.dumps(
            {"membership_id": 999999, "role": ProjectMembership.CONTRIBUTOR}
        ),
        content_type="application/json",
        **bearer(write_token),
    )

    assert_v2_error(response, "not_found", status_code=404)


@pytest.mark.django_db
def test_add_project_member_membership_from_other_organization(
    client,
    api_context,
    write_token,
    create_project,
    create_user,
    create_organization,
):
    """Return 404 when membership_id belongs to another organization."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)
    outsider = create_user(username="outsider", email="outsider@example.com")
    other_org = create_organization(name="other", user=outsider)
    other_membership = Membership.objects.get(user=outsider, organization=other_org)

    response = client.post(
        project_members_url(),
        data=json.dumps(
            {
                "membership_id": other_membership.pk,
                "role": ProjectMembership.CONTRIBUTOR,
            }
        ),
        content_type="application/json",
        **bearer(write_token),
    )

    assert_v2_error(response, "not_found", status_code=404)


@pytest.mark.django_db
def test_add_project_member_already_assigned(
    client, api_context, write_token, create_project, create_user
):
    """Reject adding a member who is already assigned to the project."""
    _user, organization, _create_token = api_context
    project = create_project(name="prod", organization=organization)
    member = create_user(username="member", email="member@example.com")
    org_membership = Membership.objects.create(
        user=member,
        organization=organization,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    ProjectMembership.objects.create(
        project=project,
        membership=org_membership,
        role=ProjectMembership.VIEWER,
    )

    response = client.post(
        project_members_url(),
        data=json.dumps(
            {
                "membership_id": org_membership.pk,
                "role": ProjectMembership.CONTRIBUTOR,
            }
        ),
        content_type="application/json",
        **bearer(write_token),
    )

    assert_v2_error(
        response,
        "validation_error",
        details={"membership": "Member already assigned to this project."},
    )


@pytest.mark.django_db
def test_add_project_member_invalid_role(
    client, api_context, write_token, create_project
):
    """Reject project member create with an invalid project role."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)
    owner_membership = organization.membership_set.get(user=_user)

    response = client.post(
        project_members_url(),
        data=json.dumps({"membership_id": owner_membership.pk, "role": "superuser"}),
        content_type="application/json",
        **bearer(write_token),
    )

    assert_v2_error(
        response,
        "validation_error",
        details={"role": ['"superuser" is not a valid choice.']},
    )


@pytest.mark.django_db
def test_project_members_unknown_project_returns_404(
    client, api_context, write_token, create_project
):
    """Return 404 when the project name does not exist."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)

    response = client.get(
        project_members_url(project_name="missing"),
        **bearer(write_token),
    )

    assert_v2_error(response, "not_found", status_code=404)


@pytest.mark.django_db
def test_project_members_wrong_organization_in_path_returns_404(
    client, api_context, write_token, create_project
):
    """Return 404 when the organization in the path does not match the token."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)

    response = client.get(
        project_members_url(org_name="wrong-org"),
        **bearer(write_token),
    )

    assert_v2_error(response, "not_found", status_code=404)


@pytest.mark.django_db
def test_project_members_inactive_project_returns_404(
    client, api_context, write_token, create_project
):
    """Return 404 when the project is inactive."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization, active=False)

    response = client.get(project_members_url(), **bearer(write_token))

    assert_v2_error(response, "not_found", status_code=404)


@pytest.mark.django_db
def test_patch_project_member_unknown_id_returns_404(
    client, api_context, write_token, create_project
):
    """Return 404 when patching a project membership id that does not exist."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)

    response = client.patch(
        project_member_detail_url(999999),
        data=json.dumps({"role": ProjectMembership.CONTRIBUTOR}),
        content_type="application/json",
        **bearer(write_token),
    )

    assert_v2_error(response, "not_found", status_code=404)


@pytest.mark.django_db
def test_patch_project_member_id_from_other_project_returns_404(
    client, api_context, write_token, create_project, create_user
):
    """Return 404 when the project membership belongs to another project."""
    _user, organization, _create_token = api_context
    project_a = create_project(name="alpha", organization=organization)
    project_b = create_project(name="beta", organization=organization)
    member = create_user(username="member", email="member@example.com")
    org_membership = Membership.objects.create(
        user=member,
        organization=organization,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    other_pm = ProjectMembership.objects.create(
        project=project_b,
        membership=org_membership,
        role=ProjectMembership.VIEWER,
    )

    response = client.patch(
        project_member_detail_url(other_pm.pk, project_name=project_a.name),
        data=json.dumps({"role": ProjectMembership.CONTRIBUTOR}),
        content_type="application/json",
        **bearer(write_token),
    )

    assert_v2_error(response, "not_found", status_code=404)


@pytest.mark.django_db
def test_list_project_members_without_project_access_returns_403(
    client, api_context, create_project, create_user, create_org_token
):
    """Reject list when the token creator has no access to the project."""
    _owner, organization, _factory = api_context
    create_project(name="prod", organization=organization)
    outsider = create_user(username="outsider", email="outsider@example.com")
    Membership.objects.create(
        user=outsider,
        organization=organization,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    token_string = create_org_token(
        created_by=outsider,
        access_mode=OrganizationAPIToken.AccessMode.WRITE,
    )

    response = client.get(project_members_url(), **bearer(token_string))

    assert response.status_code == 403
    assert response.json()["error"]["code"] in ("permission_denied", "error")


@pytest.mark.django_db
def test_add_project_member_contributor_without_manage_permission(
    client, api_context, create_project, create_user, create_org_token
):
    """Reject create when the token creator lacks project.members.manage."""
    _owner, organization, _factory = api_context
    project = create_project(name="prod", organization=organization)
    contributor = create_user(username="contrib", email="contrib@example.com")
    contributor_m = Membership.objects.create(
        user=contributor,
        organization=organization,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    ProjectMembership.objects.create(
        project=project,
        membership=contributor_m,
        role=ProjectMembership.CONTRIBUTOR,
    )
    newbie = create_user(username="newbie", email="newbie@example.com")
    newbie_m = Membership.objects.create(
        user=newbie,
        organization=organization,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    token_string = create_org_token(
        created_by=contributor,
        access_mode=OrganizationAPIToken.AccessMode.WRITE,
    )

    response = client.post(
        project_members_url(),
        data=json.dumps(
            {"membership_id": newbie_m.pk, "role": ProjectMembership.VIEWER}
        ),
        content_type="application/json",
        **bearer(token_string),
    )

    assert_v2_error(
        response,
        "validation_error",
        message="You do not have permission to manage project members.",
    )


@pytest.mark.django_db
def test_patch_own_project_role_rejected(
    client, api_context, create_project, create_user
):
    """Reject PATCH when a project admin tries to change their own project role."""
    _owner, organization, create_token_factory = api_context
    project = create_project(name="prod", organization=organization)
    admin_user = create_user(username="padmin", email="padmin@example.com")
    admin_m = Membership.objects.create(
        user=admin_user,
        organization=organization,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    project_membership = ProjectMembership.objects.create(
        project=project,
        membership=admin_m,
        role=ProjectMembership.PROJECT_ADMIN,
    )
    token_string = create_token_factory(
        created_by=admin_user,
        access_mode=OrganizationAPIToken.AccessMode.WRITE,
    )

    response = client.patch(
        project_member_detail_url(project_membership.pk),
        data=json.dumps({"role": ProjectMembership.VIEWER}),
        content_type="application/json",
        **bearer(token_string),
    )

    assert_v2_error(
        response,
        "validation_error",
        message="You cannot change your own project role.",
    )


@pytest.mark.django_db
def test_delete_own_project_membership_rejected(
    client, api_context, create_project, create_user
):
    """Reject DELETE when a project admin tries to remove themselves from the project."""
    _owner, organization, create_token_factory = api_context
    project = create_project(name="prod", organization=organization)
    admin_user = create_user(username="padmin", email="padmin@example.com")
    admin_m = Membership.objects.create(
        user=admin_user,
        organization=organization,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    project_membership = ProjectMembership.objects.create(
        project=project,
        membership=admin_m,
        role=ProjectMembership.PROJECT_ADMIN,
    )
    token_string = create_token_factory(
        created_by=admin_user,
        access_mode=OrganizationAPIToken.AccessMode.WRITE,
    )

    response = client.delete(
        project_member_detail_url(project_membership.pk),
        **bearer(token_string),
    )

    assert_v2_error(
        response,
        "validation_error",
        message="You cannot remove yourself from the project this way.",
    )


@pytest.mark.django_db
def test_project_members_post_without_api_actor_returns_403(
    client, api_context, create_org_token, create_project
):
    """Reject write operations when the token has no associated user."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)
    owner_membership = organization.membership_set.get(user=_user)
    token_string = create_org_token(
        created_by=None,
        access_mode=OrganizationAPIToken.AccessMode.WRITE,
    )

    response = client.post(
        project_members_url(),
        data=json.dumps(
            {
                "membership_id": owner_membership.pk,
                "role": ProjectMembership.CONTRIBUTOR,
            }
        ),
        content_type="application/json",
        **bearer(token_string),
    )

    assert_v2_error(
        response,
        "permission_denied",
        status_code=403,
        message="This token has no associated user for authorization.",
    )


@pytest.mark.django_db
@override_settings(API_SCOPES_ENABLED=True)
def test_project_members_read_only_token_on_post_returns_403(
    client, api_context, read_token, create_project, create_user
):
    """POST rejects read-only tokens with 403."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)
    member = create_user(username="member", email="member@example.com")
    org_membership = Membership.objects.create(
        user=member,
        organization=organization,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )

    response = client.post(
        project_members_url(),
        data=json.dumps(
            {
                "membership_id": org_membership.pk,
                "role": ProjectMembership.CONTRIBUTOR,
            }
        ),
        content_type="application/json",
        **bearer(read_token),
    )

    assert_v2_error(response, "read_only_token", status_code=403)


@pytest.mark.django_db
@override_settings(API_SCOPES_ENABLED=True)
def test_project_members_missing_projects_write_scope_returns_403(
    client, create_org_token, create_project, api_context, create_user
):
    """POST rejects tokens that lack the projects:write scope."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)
    member = create_user(username="member", email="member@example.com")
    org_membership = Membership.objects.create(
        user=member,
        organization=organization,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    token_string = create_org_token(
        access_mode=OrganizationAPIToken.AccessMode.WRITE,
        scopes=["members:write"],
    )

    response = client.post(
        project_members_url(),
        data=json.dumps(
            {
                "membership_id": org_membership.pk,
                "role": ProjectMembership.CONTRIBUTOR,
            }
        ),
        content_type="application/json",
        **bearer(token_string),
    )

    assert_v2_error(
        response,
        "missing_scope",
        status_code=403,
        required_scope="projects:write",
    )


@pytest.mark.django_db
@override_settings(API_SCOPES_ENABLED=True)
def test_project_members_missing_projects_read_scope_returns_403(
    client, create_org_token, create_project, api_context
):
    """GET rejects tokens that lack the projects:read scope."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)
    token_string = create_org_token(
        access_mode=OrganizationAPIToken.AccessMode.WRITE,
        scopes=["members:read"],
    )

    response = client.get(project_members_url(), **bearer(token_string))

    assert_v2_error(
        response,
        "missing_scope",
        status_code=403,
        required_scope="projects:read",
    )
