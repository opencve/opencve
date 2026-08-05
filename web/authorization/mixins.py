from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect
from django.urls import reverse

from authorization.context import get_authorization_context


class RequiresOrgPermissionMixin:
    """Redirect to org list when required_org_permission is missing."""

    required_org_permission = None

    def dispatch(self, request, *args, **kwargs):
        if not request.current_organization:
            return redirect("list_organizations")
        if self.required_org_permission:
            ctx = get_authorization_context(request)
            if not ctx.has_org_permission(self.required_org_permission):
                messages.error(
                    request, "You do not have permission to perform this action."
                )
                return redirect("list_organizations")
        return super().dispatch(request, *args, **kwargs)


class RequiresProjectPermissionMixin:
    """Must be listed after ProjectObjectMixin in view class bases."""

    required_project_permission = None
    # Not named permission_denied_message: LoginRequiredMixin's AccessMixin
    # defines that attribute as "" and wins MRO lookup on project views.
    project_permission_denied_message = (
        "You do not have permission to perform this action."
    )

    def dispatch(self, request, *args, **kwargs):
        if self.required_project_permission and hasattr(self, "project"):
            ctx = get_authorization_context(request)
            if not ctx.has_project_permission(
                self.project, self.required_project_permission
            ):
                if self.should_redirect_on_permission_denied(request):
                    messages.error(
                        request, self.get_project_permission_denied_message()
                    )
                    return redirect(self.get_permission_denied_redirect_url(request))
                raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)

    def should_redirect_on_permission_denied(self, request):
        # AJAX/JSON clients get 403; browser navigation gets redirect + flash.
        accept = request.headers.get("Accept", "")
        if "application/json" in accept and "text/html" not in accept:
            return False
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return False
        return True

    def get_project_permission_denied_message(self):
        return self.project_permission_denied_message

    def get_permission_denied_redirect_url(self, request):
        return reverse(
            "project",
            kwargs={
                "org_name": request.current_organization.name,
                "project_name": self.project.name,
            },
        )
