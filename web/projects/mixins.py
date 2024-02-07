from django.http import Http404
from django.shortcuts import get_object_or_404, redirect

from organizations.models import Membership


class OrganizationIsOwnerMixin:
    """Check if the user is owner of the organization"""

    def dispatch(self, request, *args, **kwargs):
        organization = self.get_object()
        if not Membership.objects.filter(
            user=request.user, organization=organization, role=Membership.OWNER
        ).exists():
            raise Http404()
        return super().dispatch(request, *args, **kwargs)
