from rest_framework import authentication
from rest_framework.authentication import get_authorization_header
from rest_framework.exceptions import AuthenticationFailed

from organizations.models import OrganizationAPIToken


class OrganizationTokenAuthentication(authentication.BaseAuthentication):
    """
    Authentication class for organization API tokens.

    Token format: opc_org.<token_id>.<secret>
    Usage: Authorization: Bearer opc_org.<token_id>.<secret>
    """

    def authenticate(self, request):
        auth_header = get_authorization_header(request).decode("utf-8")

        if not auth_header.startswith("Bearer "):
            return None

        token = auth_header[7:].strip()

        if not token.startswith(f"{OrganizationAPIToken.TOKEN_PREFIX}."):
            return None

        try:
            parts = token.split(".", 2)
            if len(parts) != 3 or parts[0] != OrganizationAPIToken.TOKEN_PREFIX:
                return None

            token_id = parts[1]
            secret = parts[2]
        except (ValueError, IndexError):
            return None

        try:
            api_token = OrganizationAPIToken.objects.select_related(
                "organization", "created_by"
            ).get(token_id=token_id, is_active=True)
        except OrganizationAPIToken.DoesNotExist:
            raise AuthenticationFailed("Invalid token.")

        if not api_token.verify_token(secret):
            raise AuthenticationFailed("Invalid token.")

        api_token.update_last_used()
        request.authenticated_organization = api_token.organization
        request.api_token = api_token

        return (api_token.created_by, None)
