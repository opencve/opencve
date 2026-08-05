import pytest
from django.utils.timezone import now

from authorization.context_processors import accessible_projects_for_request
from authorization.roles import PROJECT_VIEWER
from organizations.models import Membership
from projects.models import ProjectMembership


@pytest.mark.django_db
def test_accessible_projects_context_processor_lists_member_projects(
    rf, create_user, create_organization, create_project, create_project_membership
):
    """Context processor exposes only projects the user can access in the sidebar."""
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

    request = rf.get("/")
    request.user = member
    request.current_organization = org

    context = accessible_projects_for_request(request)
    names = [p.name for p in context["accessible_projects"]]

    assert names == ["alpha"]
