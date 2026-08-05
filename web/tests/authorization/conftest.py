import json

import pytest
from django.urls import reverse
from django.utils.timezone import now

from organizations.models import Membership
from projects.models import ProjectMembership


@pytest.fixture
def create_project_membership():
    def _create_project_membership(*, project, membership, role):
        return ProjectMembership.objects.create(
            project=project,
            membership=membership,
            role=role,
        )

    return _create_project_membership


@pytest.fixture
def create_org_membership(create_user):
    def _create_org_membership(*, organization, user=None, role=Membership.MEMBER):
        user = user or create_user()
        return Membership.objects.create(
            user=user,
            organization=organization,
            role=role,
            date_invited=now(),
            date_joined=now(),
        )

    return _create_org_membership


@pytest.fixture
def set_current_org(auth_client):
    def _set_current_org(client, organization):
        session = client.session
        session["current_organization_id"] = str(organization.id)
        session.save()
        return client

    return _set_current_org


def assert_redirect_with_message(response, *, url, message):
    """Assert response is a redirect to url with a flash message."""
    assert response.status_code == 302
    assert response.url == url
    messages = list(response.wsgi_request._messages)
    assert any(message in m.message for m in messages)


def assert_permission_denied_json(response):
    """Assert JSON response is a 403 permission denied."""
    assert response.status_code == 403
    data = json.loads(response.content)
    assert data.get("error") or response.status_code == 403


def org_member_with_project_role(
    *,
    create_user,
    create_organization,
    create_project,
    create_project_membership,
    org_owner,
    member_role=Membership.MEMBER,
    project_role,
    project_name="project1",
    org_name="org1",
):
    """Build org + project with a member holding the given project role."""
    org = create_organization(name=org_name, user=org_owner)
    membership = Membership.objects.create(
        user=create_user(),
        organization=org,
        role=member_role,
        date_invited=now(),
        date_joined=now(),
    )
    project = create_project(name=project_name, organization=org)
    create_project_membership(project=project, membership=membership, role=project_role)
    return org, project, membership.user
