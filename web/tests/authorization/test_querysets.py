import pytest
from django.utils.timezone import now

from authorization.querysets import (
    accessible_projects,
    get_project_for_user,
    subscription_manageable_projects,
)
from authorization.roles import PROJECT_ADMIN, PROJECT_CONTRIBUTOR, PROJECT_VIEWER
from organizations.models import Membership
from projects.models import ProjectMembership


@pytest.mark.django_db
def test_accessible_projects_org_owner_sees_all(
    create_user, create_organization, create_project
):
    """Org owner sees every project in the organization."""
    owner = create_user(username="owner")
    org = create_organization(name="org1", user=owner)
    create_project(name="alpha", organization=org)
    create_project(name="beta", organization=org)

    qs = accessible_projects(owner, org)
    assert set(qs.values_list("name", flat=True)) == {"alpha", "beta"}


@pytest.mark.django_db
def test_accessible_projects_member_sees_explicit_memberships_only(
    create_user, create_organization, create_project, create_project_membership
):
    """Org member only sees projects with explicit ProjectMembership."""
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
    alpha = create_project(name="alpha", organization=org)
    create_project(name="beta", organization=org)
    create_project_membership(project=alpha, membership=member_m, role=PROJECT_VIEWER)

    qs = accessible_projects(member, org)
    assert list(qs.values_list("name", flat=True)) == ["alpha"]


@pytest.mark.django_db
def test_get_project_for_user_returns_none_without_access(
    create_user, create_organization, create_project
):
    """get_project_for_user returns None when the user has no project access."""
    owner = create_user(username="owner")
    outsider = create_user(username="outsider")
    org = create_organization(name="org1", user=owner)
    create_project(name="alpha", organization=org)

    assert get_project_for_user(owner, org, "alpha") is not None
    assert get_project_for_user(outsider, org, "alpha") is None


@pytest.mark.django_db
def test_subscription_manageable_projects_project_admin_only(
    create_user, create_organization, create_project, create_project_membership
):
    """Only active projects where user is project admin are subscription-manageable."""
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
    admin_project = create_project(name="admin-proj", organization=org, active=True)
    contributor_project = create_project(
        name="contrib-proj", organization=org, active=True
    )
    create_project(name="inactive-admin", organization=org, active=False)
    create_project_membership(
        project=admin_project, membership=member_m, role=PROJECT_ADMIN
    )
    create_project_membership(
        project=contributor_project,
        membership=member_m,
        role=PROJECT_CONTRIBUTOR,
    )

    qs = subscription_manageable_projects(member, org)
    assert list(qs.values_list("name", flat=True)) == ["admin-proj"]
