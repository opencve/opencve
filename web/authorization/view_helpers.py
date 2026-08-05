from django.core.exceptions import PermissionDenied

from authorization.context import get_authorization_context


def check_project_permission(request, project, permission):
    """Raise PermissionDenied when the user lacks a project permission."""
    ctx = get_authorization_context(request)
    if not ctx.has_project_permission(project, permission):
        raise PermissionDenied
