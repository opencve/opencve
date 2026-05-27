from django.contrib import messages
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect

from projects.models import Project


class ProjectObjectMixin:
    """Populate the self.project object"""

    def dispatch(self, request, *args, **kwargs):
        try:
            self.project = get_object_or_404(
                Project,
                organization=self.request.current_organization,
                name=self.kwargs["project_name"],
            )
        except Http404:
            if request.current_organization:
                messages.error(request, "The requested project does not exist.")
                return redirect(
                    "list_projects",
                    org_name=request.current_organization.name,
                )
            raise
        return super().dispatch(request, *args, **kwargs)

    def get_object(self, queryset=None):
        return self.project


class ProjectIsActiveMixin:
    """Check if a project is active or not"""

    def dispatch(self, request, *args, **kwargs):
        if not self.project.active:
            raise Http404

        return super().dispatch(request, *args, **kwargs)


class ResourceUrlNameMixin:
    """Expose the persisted resource slug from URL kwargs for template links."""

    resource_url_kwarg = None

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if self.resource_url_kwarg:
            context[f"{self.resource_url_kwarg}_url_name"] = self.kwargs[
                self.resource_url_kwarg
            ]
        return context
