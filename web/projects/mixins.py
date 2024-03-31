from django.shortcuts import get_object_or_404

from organizations.models import Organization
from projects.models import Project


class ProjectObjectMixin:
    """
    Provides a project object based on the organization
    and project names given in url.
    """

    def get_object(self, queryset=None):
        return get_object_or_404(
            Project,
            organization=self.request.user_organization,
            name=self.kwargs["project_name"],
        )


class ProjectIsActiveMixin:
    """Check if a project is active or not"""

    def dispatch(self, request, *args, **kwargs):
        organization = get_object_or_404(
            Organization, members=request.user, name=kwargs["org_name"]
        )

        _ = get_object_or_404(
            Project, organization=organization, name=kwargs["project_name"], active=True
        )

        return super().dispatch(request, *args, **kwargs)
