from django.urls import path, re_path

from organizations.views import (
    OrganizationCreateView,
    OrganizationDeleteView,
    OrganizationEditView,
    OrganizationEditMembersView,
    OrganizationEditTokensView,
    OrganizationInvitationView,
    OrganizationMemberDeleteView,
    OrganizationMemberRoleUpdateView,
    OrganizationTokenDeleteView,
    OrganizationsListView,
    change_organization,
)

urlpatterns = [
    path("ajax/change_organization", change_organization, name="change_organization"),
    path("org/", OrganizationsListView.as_view(), name="list_organizations"),
    path("org/add", OrganizationCreateView.as_view(), name="create_organization"),
    path("org/<org_name>", OrganizationEditView.as_view(), name="edit_organization"),
    path(
        "org/<org_name>/tokens",
        OrganizationEditTokensView.as_view(),
        name="edit_organization_tokens",
    ),
    path(
        "org/<org_name>/delete",
        OrganizationDeleteView.as_view(),
        name="delete_organization",
    ),
    path(
        "org/<org_name>/members",
        OrganizationEditMembersView.as_view(),
        name="edit_organization_members",
    ),
    path(
        "org/<org_name>/members/<member_id>/delete",
        OrganizationMemberDeleteView.as_view(),
        name="delete_organization_member",
    ),
    path(
        "org/<org_name>/members/<member_id>/role",
        OrganizationMemberRoleUpdateView.as_view(),
        name="update_organization_member_role",
    ),
    path(
        "org/<org_name>/invitation/<key>",
        OrganizationInvitationView.as_view(),
        name="accept_organization_invitation",
    ),
    path(
        "org/<org_name>/tokens/<token_id>/revoke",
        OrganizationTokenDeleteView.as_view(),
        name="revoke_organization_token",
    ),
]
