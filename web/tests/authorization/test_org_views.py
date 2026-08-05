import pytest
from django.test import override_settings
from django.urls import reverse
from django.utils.timezone import now

from organizations.models import Membership


@override_settings(ENABLE_ONBOARDING=False)
def test_edit_organization_admin_cannot_access_audit_logs(
    auth_client, create_user, create_organization
):
    """Org admin is denied access to audit logs."""
    owner = create_user(username="owner", email="owner@example.com")
    admin = create_user(username="admin", email="admin@example.com")
    organization = create_organization(name="orga1", user=owner, owner=True)
    Membership.objects.create(
        organization=organization,
        user=admin,
        role=Membership.ADMIN,
        date_joined=now(),
    )
    client = auth_client(admin)
    url = reverse(
        "edit_organization_audit_logs", kwargs={"org_name": organization.name}
    )

    response = client.get(url)

    assert response.status_code == 302
    assert response.url == reverse("list_organizations")


@override_settings(ENABLE_ONBOARDING=False)
def test_outsider_cannot_access_foreign_org_projects(
    auth_client, create_user, create_organization
):
    """User from another organization is redirected when accessing foreign org projects."""
    owner = create_user(username="owner")
    outsider = create_user(username="outsider")
    create_organization(name="acl-demo", user=owner)
    create_organization(name="acl-other", user=outsider)

    response = auth_client(outsider).get(
        reverse("list_projects", kwargs={"org_name": "acl-demo"}),
    )

    assert response.status_code == 302
    assert response.url == reverse("list_organizations")
