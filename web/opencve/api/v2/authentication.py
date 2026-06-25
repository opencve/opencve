from rest_framework import authentication
from rest_framework.authentication import get_authorization_header
from rest_framework.exceptions import AuthenticationFailed

from organizations.models import OrganizationAPIToken


class V2OrganizationTokenAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        auth_header = get_authorization_header(request).decode("utf-8")
        if not auth_header.startswith("Bearer "):
            return None
        token_string = auth_header[7:].strip()
        if not token_string.startswith(f"{OrganizationAPIToken.TOKEN_PREFIX}."):
            return None
        try:
            parts = token_string.split(".", 2)
            if len(parts) != 3 or parts[0] != OrganizationAPIToken.TOKEN_PREFIX:
                return None
            token_id, secret = parts[1], parts[2]
        except (ValueError, IndexError):
            return None
        try:
            org_token = OrganizationAPIToken.objects.select_related(
                "organization", "created_by"
            ).get(token_id=token_id, is_active=True)
        except OrganizationAPIToken.DoesNotExist:
            raise AuthenticationFailed("Invalid token.")
        if not org_token.verify_token(secret):
            raise AuthenticationFailed("Invalid token.")
        org_token.update_last_used()
        request.authenticated_organization = org_token.organization
        request.organization_token = org_token
        request.api_token = org_token
        request.api_actor = org_token.created_by
        return (org_token.created_by, org_token)
