import pytest
from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import HttpResponse
from django.urls import reverse
from django.views import View

from organizations.mixins import (
    OrganizationIsMemberMixin,
    OrganizationRequiredMixin,
)


def _add_session_and_messages(request):
    """
    Attach a session and message storage to the request so that
    mixins using django.contrib.messages can work with RequestFactory.
    """
    middleware = SessionMiddleware(lambda r: None)
    middleware.process_request(request)
    request.session.save()
    setattr(request, "_messages", FallbackStorage(request))


class _OrganizationRequiredView(OrganizationRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        return HttpResponse("ok")


class _OrganizationIsMemberView(OrganizationIsMemberMixin, View):
    def get(self, request, *args, **kwargs):
        return HttpResponse("ok")


@pytest.mark.django_db
def test_organization_required_mixin_without_organization(create_user, rf):
    user = create_user()
    request = rf.get("/")
    request.user = user
    request.current_organization = None

    view = _OrganizationRequiredView.as_view()
    response = view(request)

    assert response.status_code == 302
    assert response.url == reverse("list_organizations")


@pytest.mark.django_db
def test_organization_required_mixin_with_organization(
    create_user, create_organization, rf
):
    user = create_user()
    organization = create_organization(name="orga1", user=user, owner=True)

    request = rf.get("/")
    request.user = user
    request.current_organization = organization

    view = _OrganizationRequiredView.as_view()
    response = view(request)

    # When an organization is present, the mixin should call super().dispatch
    # and not perform a redirect.
    assert response.status_code == 200
    assert response.content == b"ok"


@pytest.mark.django_db
def test_organization_is_member_mixin_without_organization(create_user, rf):
    user = create_user()
    request = rf.get("/")
    request.user = user
    request.current_organization = None
    _add_session_and_messages(request)

    view = _OrganizationIsMemberView.as_view()
    response = view(request)

    assert response.status_code == 302
    assert response.url == reverse("list_organizations")
    messages = list(request._messages)
    assert any(
        message.message == "The requested organization does not exist."
        for message in messages
    )


@pytest.mark.django_db
def test_organization_is_member_mixin_with_organization(
    create_user, create_organization, rf
):
    user = create_user()
    organization = create_organization(name="orga1", user=user, owner=True)

    request = rf.get("/")
    request.user = user
    request.current_organization = organization
    _add_session_and_messages(request)

    view = _OrganizationIsMemberView.as_view()
    response = view(request)

    # When an organization is present, the mixin should pass through without redirect.
    assert response.status_code == 200
    assert response.content == b"ok"
    messages = list(request._messages)
    assert not messages
