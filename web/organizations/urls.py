from django.urls import path, re_path

from organizations.views import change_organization, OrganizationCreateView, OrganizationDeleteView, OrganizationEditView, OrganizationsListView, OrganizationMembersFormView, OrganizationInvitationView

urlpatterns = [
    path("ajax/change_organization", change_organization, name="change_organization"),
    path("org/", OrganizationsListView.as_view(), name="list_organizations"),
    path("org/add", OrganizationCreateView.as_view(), name="create_organization"),
    path("org/<name>/edit", OrganizationEditView.as_view(), name="edit_organization"),
    path("org/<name>/delete", OrganizationDeleteView.as_view(), name="delete_organization"),
    path("org/<name>/members", OrganizationMembersFormView.as_view(), name="list_organization_members"),
    path("org/<name>/invitation/<key>", OrganizationInvitationView.as_view(), name="accept_organization_invitation"),
]
