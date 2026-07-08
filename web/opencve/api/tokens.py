from rest_framework.authentication import get_authorization_header
from rest_framework.exceptions import AuthenticationFailed

from organizations.models import OrganizationAPIToken


def authenticate_organization_token(request):
    """
    Parse and verify an organization Bearer token from the request.

    Returns the OrganizationAPIToken, or None if the header is absent or not
    an organization token. Raises AuthenticationFailed when the token is invalid.
    """
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
        raise AuthenticationFailed("Invalid token.") from None

    if not org_token.verify_token(secret):
        raise AuthenticationFailed("Invalid token.")

    return org_token


def bind_organization_token(request, org_token):
    """Attach authenticated organization token metadata to the request."""
    org_token.update_last_used()
    request.authenticated_organization = org_token.organization
    request.api_token = org_token
