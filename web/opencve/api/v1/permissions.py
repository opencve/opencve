from rest_framework import permissions


class IsAuthenticatedOrOrganizationToken(permissions.IsAuthenticated):
    """Allow authenticated users or valid organization API tokens."""

    def has_permission(self, request, view):
        if request.user and request.user.is_authenticated:
            return True
        if hasattr(request, "authenticated_organization"):
            return True
        return False
