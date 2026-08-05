import pytest
from django.utils.timezone import now

from authorization.context import AuthorizationContext
from authorization.permissions import (
    PROJECT_AUTOMATIONS_MANAGE,
    PROJECT_TRACKER_ASSIGN,
    PROJECT_VIEW,
)
from authorization.roles import PROJECT_CONTRIBUTOR, PROJECT_VIEWER
from organizations.models import Membership


@pytest.mark.django_db
def test_authorization_context_caches_project_permissions(
    create_user, create_organization, create_project, create_project_membership
):
    """Project permissions are cached per project on AuthorizationContext."""
    owner = create_user(username="owner")
    member = create_user(username="member")
    org = create_organization(name="org1", user=owner)
    member_m = Membership.objects.create(
        user=member,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    project = create_project(name="project1", organization=org)
    create_project_membership(project=project, membership=member_m, role=PROJECT_VIEWER)

    ctx = AuthorizationContext(member, org)
    perms_first = ctx.project_permissions(project)
    perms_second = ctx.project_permissions(project)

    assert perms_first is perms_second
    assert PROJECT_VIEW in perms_first
    assert PROJECT_TRACKER_ASSIGN not in perms_first
    assert PROJECT_AUTOMATIONS_MANAGE not in perms_first


@pytest.mark.django_db
def test_org_owner_has_implicit_project_admin(
    create_user, create_organization, create_project
):
    """Org owner gets project admin permissions without explicit membership."""
    owner = create_user(username="owner")
    org = create_organization(name="org1", user=owner)
    project = create_project(name="project1", organization=org)

    ctx = AuthorizationContext(owner, org)
    assert ctx.has_project_permission(project, PROJECT_AUTOMATIONS_MANAGE) is True
    assert ctx.has_project_permission(project, PROJECT_TRACKER_ASSIGN) is True
