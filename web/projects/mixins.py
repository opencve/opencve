from django.shortcuts import get_object_or_404

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
