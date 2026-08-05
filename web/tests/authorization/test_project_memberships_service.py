import pytest
from django.utils.timezone import now
from rest_framework.exceptions import ValidationError

from authorization.roles import PROJECT_ADMIN, PROJECT_CONTRIBUTOR, PROJECT_VIEWER
from organizations.models import Membership
from projects.models import ProjectMembership
from projects.services.project_memberships import (
    add_project_member,
    remove_project_member,
    update_project_member_role,
)


@pytest.mark.django_db
def test_add_project_member_requires_manage_permission(
    create_user, create_organization, create_project, create_project_membership
):
    """Contributor cannot add project members."""
    owner = create_user(username="owner")
    contributor = create_user(username="contributor")
    new_member = create_user(username="newbie")
    org = create_organization(name="org1", user=owner)
    contributor_m = Membership.objects.create(
        user=contributor,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    newbie_m = Membership.objects.create(
        user=new_member,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    project = create_project(name="project1", organization=org)
    create_project_membership(
        project=project, membership=contributor_m, role=PROJECT_CONTRIBUTOR
    )

    with pytest.raises(ValidationError, match="permission"):
        add_project_member(
            project=project,
            membership=newbie_m,
            role=PROJECT_VIEWER,
            actor_user=contributor,
            actor_organization=org,
        )


@pytest.mark.django_db
def test_project_admin_can_add_member(
    create_user, create_organization, create_project, create_project_membership
):
    """Project admin can add a new project member."""
    owner = create_user(username="owner")
    admin_user = create_user(username="padmin")
    new_member = create_user(username="newbie")
    org = create_organization(name="org1", user=owner)
    admin_m = Membership.objects.create(
        user=admin_user,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    newbie_m = Membership.objects.create(
        user=new_member,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    project = create_project(name="project1", organization=org)
    create_project_membership(project=project, membership=admin_m, role=PROJECT_ADMIN)

    pm = add_project_member(
        project=project,
        membership=newbie_m,
        role=PROJECT_VIEWER,
        actor_user=admin_user,
        actor_organization=org,
    )

    assert pm.role == PROJECT_VIEWER
    assert ProjectMembership.objects.filter(
        project=project, membership=newbie_m
    ).exists()


@pytest.mark.django_db
def test_contributor_cannot_change_project_role(
    create_user, create_organization, create_project, create_project_membership
):
    """Contributor cannot promote another member via update_project_member_role."""
    owner = create_user(username="owner")
    contributor = create_user(username="contributor")
    viewer = create_user(username="viewer")
    org = create_organization(name="org1", user=owner)
    contributor_m = Membership.objects.create(
        user=contributor,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    viewer_m = Membership.objects.create(
        user=viewer,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    project = create_project(name="project1", organization=org)
    create_project_membership(
        project=project, membership=contributor_m, role=PROJECT_CONTRIBUTOR
    )
    viewer_pm = ProjectMembership.objects.create(
        project=project, membership=viewer_m, role=PROJECT_VIEWER
    )

    with pytest.raises(ValidationError, match="permission"):
        update_project_member_role(
            project_membership=viewer_pm,
            role=PROJECT_CONTRIBUTOR,
            actor_user=contributor,
            actor_organization=org,
        )


@pytest.mark.django_db
def test_project_admin_can_remove_member(
    create_user, create_organization, create_project, create_project_membership
):
    """Project admin can remove another project member."""
    owner = create_user(username="owner")
    admin_user = create_user(username="padmin")
    viewer = create_user(username="viewer")
    org = create_organization(name="org1", user=owner)
    admin_m = Membership.objects.create(
        user=admin_user,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    viewer_m = Membership.objects.create(
        user=viewer,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    project = create_project(name="project1", organization=org)
    create_project_membership(project=project, membership=admin_m, role=PROJECT_ADMIN)
    viewer_pm = ProjectMembership.objects.create(
        project=project, membership=viewer_m, role=PROJECT_VIEWER
    )

    remove_project_member(
        project_membership=viewer_pm,
        actor_user=admin_user,
        actor_organization=org,
    )

    assert not ProjectMembership.objects.filter(pk=viewer_pm.pk).exists()
