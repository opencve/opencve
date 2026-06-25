from rest_framework import permissions
from rest_framework.exceptions import PermissionDenied

from opencve.api.scopes import APIScope, token_has_scope


class IsV2OrganizationTokenAuthenticated(permissions.BasePermission):
    def has_permission(self, request, view):
        return bool(getattr(request, "organization_token", None))


class RequiresScope(permissions.BasePermission):
    def __init__(self, scope: APIScope | None = None):
        self.scope = scope

    def has_permission(self, request, view):
        token = getattr(request, "organization_token", None)
        if not token:
            return False
        if self.scope is None:
            return True
        if not token_has_scope(token, self.scope):
            if (
                self.scope.value.endswith(":write")
                and token.access_mode == token.AccessMode.READ
            ):
                raise ReadOnlyToken()
            raise MissingScope(required_scope=self.scope.value)
        return True


class ReadOnlyToken(PermissionDenied):
    default_code = "read_only_token"

    def __init__(self):
        super().__init__(
            detail="This token is read-only and cannot perform write operations.",
            code=self.default_code,
        )


class MissingScope(PermissionDenied):
    default_code = "missing_scope"

    def __init__(self, required_scope=None):
        self.required_scope = required_scope
        super().__init__(
            detail="The token does not have the required scope for this operation.",
            code=self.default_code,
        )
