from django.http import Http404
from django.shortcuts import get_object_or_404, redirect

from organizations.models import Membership, Organization


class OrganizationRequiredMixin:
    """Verify that the current user is member of an organization."""

    def dispatch(self, request, *args, **kwargs):
        if not request.current_organization:
            return redirect("list_organizations")
        return super().dispatch(request, *args, **kwargs)


class OrganizationIsMemberMixin:
    """Check if the user is member of the organization"""

    def dispatch(self, request, *args, **kwargs):
        if not request.current_organization:
            raise Http404

        return super().dispatch(request, *args, **kwargs)


class OrganizationIsOwnerMixin:
    """Check if the user is owner of the organization"""

    def dispatch(self, request, *args, **kwargs):
        if not request.current_organization:
            raise Http404

        # Check if user is owner
        membership = get_object_or_404(
            Membership,
            user=request.user,
            organization=request.current_organization,
            role=Membership.OWNER,
        )

        # Check if user is not just invited
        if membership.is_invited:
            raise Http404()

        return super().dispatch(request, *args, **kwargs)
