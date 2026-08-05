import pytest
from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse
from django.urls import reverse
from django.utils.timezone import now
from django.views import View

from authorization.mixins import (
    RequiresOrgPermissionMixin,
    RequiresProjectPermissionMixin,
)
from authorization.permissions import ORG_MEMBERS_VIEW, PROJECT_EDIT
from organizations.models import Membership, Organization
from projects.models import Project, ProjectMembership


def _add_session_and_messages(request):
    middleware = SessionMiddleware(lambda r: None)
    middleware.process_request(request)
    request.session.save()
    setattr(request, "_messages", FallbackStorage(request))


class _RequiresOrgPermissionView(RequiresOrgPermissionMixin, View):
    required_org_permission = ORG_MEMBERS_VIEW

    def get(self, request, *args, **kwargs):
        return HttpResponse("ok")


class _RequiresProjectPermissionView(RequiresProjectPermissionMixin, View):
    required_project_permission = PROJECT_EDIT

    def dispatch(self, request, *args, **kwargs):
        self.project = kwargs["project"]
        return super().dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        return HttpResponse("ok")


@pytest.mark.django_db
def test_requires_org_permission_mixin_denies_member(create_user, rf):
    """Org member without ORG_MEMBERS_VIEW is redirected to list_organizations."""
    user = create_user()
    org = Organization.objects.create(name="org1")
    Membership.objects.create(
        user=user,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    request = rf.get("/")
    request.user = user
    request.current_organization = org
    _add_session_and_messages(request)

    response = _RequiresOrgPermissionView.as_view()(request)

    assert response.status_code == 302
    assert response.url == reverse("list_organizations")


@pytest.mark.django_db
def test_requires_project_permission_mixin_returns_403_for_ajax(
    create_user, create_project, create_project_membership, rf
):
    """Project permission mixin returns 403 for AJAX requests."""
    owner = create_user(username="owner")
    viewer = create_user(username="viewer")
    org = Organization.objects.create(name="org1")
    Membership.objects.create(
        user=owner,
        organization=org,
        role=Membership.OWNER,
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
        project=project, membership=viewer_m, role=ProjectMembership.VIEWER
    )

    request = rf.get("/", HTTP_X_REQUESTED_WITH="XMLHttpRequest")
    request.user = viewer
    request.current_organization = org
    _add_session_and_messages(request)

    with pytest.raises(PermissionDenied):
        _RequiresProjectPermissionView.as_view()(request, project=project)
