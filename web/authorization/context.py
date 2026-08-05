from authorization.policies import (
    get_active_membership,
    get_org_permissions,
    get_project_permissions,
)
from authorization.querysets import accessible_projects


class AuthorizationContext:
    """Per-request authorization state with cached org and project permission lookups."""

    def __init__(self, user, organization):
        self.user = user
        self.organization = organization
        self._membership = None
        self._project_permissions_cache: dict = {}

    @property
    def membership(self):
        if self._membership is None and self.user and self.organization:
            self._membership = get_active_membership(self.user, self.organization)
        return self._membership

    def org_permissions(self) -> frozenset[str]:
        """Resolved organization permissions for the current user."""
        return get_org_permissions(self.membership)

    def has_org_permission(self, permission: str) -> bool:
        return permission in self.org_permissions()

    def project_permissions(self, project) -> frozenset[str]:
        """Resolved project permissions for the current user (cached per project)."""
        project_id = project.pk
        if project_id not in self._project_permissions_cache:
            self._project_permissions_cache[project_id] = get_project_permissions(
                self.user, self.organization, project
            )
        return self._project_permissions_cache[project_id]

    def has_project_permission(self, project, permission: str) -> bool:
        return permission in self.project_permissions(project)

    def accessible_projects(self):
        """Queryset of projects the current user may access in the organization."""
        return accessible_projects(self.user, self.organization)


def get_authorization_context(request):
    """Return a cached AuthorizationContext for the current request."""
    if not hasattr(request, "_authorization_context"):
        org = getattr(request, "current_organization", None)
        user = request.user if request.user.is_authenticated else None
        request._authorization_context = AuthorizationContext(user, org)
    return request._authorization_context
