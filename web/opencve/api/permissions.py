from rest_framework import permissions

from opencve.api.exceptions import InsufficientScope
from opencve.api.scopes import (
    APIScope,
    token_has_scope,
    user_can_write_org,
    user_is_org_member,
)


class IsAuthenticatedOrOrganizationToken(permissions.IsAuthenticated):
    """Allow authenticated users or valid organization API tokens."""

    def has_permission(self, request, view):
        if request.user and request.user.is_authenticated:
            return True
        if hasattr(request, "authenticated_organization"):
            return True
        return False


def scoped_permission(scope: APIScope, owner_only=False):
    """Factory for DRF permission classes bound to a specific API scope."""

    class _RequiresAPIScope(permissions.BasePermission):
        def has_permission(self, request, view):
            api_token = getattr(request, "api_token", None)
            if api_token:
                if not token_has_scope(api_token, scope):
                    raise InsufficientScope(required_scope=scope.value)
                return True

            if not request.user or not request.user.is_authenticated:
                return False

            organization = getattr(view, "organization", None)
            if organization and owner_only:
                return user_can_write_org(request.user, organization)
            if organization and scope.value.endswith(":write"):
                return user_is_org_member(request.user, organization)

            return True

    return _RequiresAPIScope


class RequiresAPIScope(permissions.BasePermission):
    """Base class; use scoped_permission() factory instead."""

    scope = None
    owner_only = False

    def has_permission(self, request, view):
        if self.scope is None:
            return True
        return scoped_permission(
            self.scope, owner_only=self.owner_only
        )().has_permission(request, view)
