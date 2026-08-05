from django.contrib import messages
from django.shortcuts import redirect

from authorization.context import get_authorization_context
from authorization.permissions import ORG_VIEW
from authorization.policies import get_active_membership
from authorization.mixins import RequiresOrgPermissionMixin


class OrganizationRequiredMixin:
    """Verify that the current user is member of an organization."""

    def dispatch(self, request, *args, **kwargs):
        if not request.current_organization:
            return redirect("list_organizations")
        return super().dispatch(request, *args, **kwargs)


class OrganizationIsMemberMixin:
    """Check if the user is an active member of the organization."""

    def dispatch(self, request, *args, **kwargs):
        if not request.current_organization:
            messages.error(request, "The requested organization does not exist.")
            return redirect("list_organizations")

        membership = get_active_membership(request.user, request.current_organization)
        if membership is None:
            messages.error(request, "The requested organization does not exist.")
            return redirect("list_organizations")

        if not get_authorization_context(request).has_org_permission(ORG_VIEW):
            messages.error(request, "The requested organization does not exist.")
            return redirect("list_organizations")

        return super().dispatch(request, *args, **kwargs)


__all__ = [
    "OrganizationRequiredMixin",
    "OrganizationIsMemberMixin",
    "RequiresOrgPermissionMixin",
]
