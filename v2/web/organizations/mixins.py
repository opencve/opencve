from django.http import Http404
from django.shortcuts import get_object_or_404, redirect

from organizations.models import Membership, Organization


class OrganizationRequiredMixin:
    """Verify that the current user is member of an organization."""

    def dispatch(self, request, *args, **kwargs):
        if not request.user_organization:
            return redirect("list_organizations")
        return super().dispatch(request, *args, **kwargs)


class OrganizationIsOwnerMixin:
    """Check if the user is owner of the organization"""
    def dispatch(self, request, *args, **kwargs):
        organization = self.get_object()
        if not Membership.objects.filter(user=request.user, organization=organization, role=Membership.OWNER).exists():
            raise Http404()
        return super().dispatch(request, *args, **kwargs)

    def get_object(self, queryset=None):
        return get_object_or_404(
            Organization, members=self.request.user, name=self.kwargs["name"]
        )

