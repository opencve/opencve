from django.contrib import messages
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
            messages.error(request, "The requested organization does not exist.")
            return redirect("list_organizations")

        return super().dispatch(request, *args, **kwargs)


class OrganizationIsOwnerMixin:
    """Check if the user is owner of the organization"""

    def dispatch(self, request, *args, **kwargs):
        if not request.current_organization:
            messages.error(request, "The requested organization does not exist.")
            return redirect("list_organizations")

        # Check if user is owner or member
        try:
            membership = get_object_or_404(
                Membership,
                user=request.user,
                organization=request.current_organization,
                role__in=[Membership.OWNER, Membership.MEMBER],
            )
        except Http404:
            messages.error(request, "The requested organization does not exist.")
            return redirect("list_organizations")

        # The user is member but not owner
        if membership.role == Membership.MEMBER:
            messages.error(request, "You are not an owner of the organization.")
            return redirect("list_organizations")

        # The user is invited but not yet joined the organization
        if membership.is_invited:
            messages.error(request, "The requested organization does not exist.")
            return redirect("list_organizations")

        return super().dispatch(request, *args, **kwargs)
