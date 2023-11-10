from django.shortcuts import redirect


class OrganizationRequiredMixin:
    """Verify that the current user is member of an organization."""

    def dispatch(self, request, *args, **kwargs):
        _dispatch = super().dispatch(request, *args, **kwargs)
        if not request.user_organization:
            return redirect("list_organizations")
        return _dispatch
