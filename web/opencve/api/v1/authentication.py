from rest_framework import authentication

from opencve.api.tokens import authenticate_organization_token, bind_organization_token


class OrganizationTokenAuthentication(authentication.BaseAuthentication):
    """
    Authentication class for organization API tokens (v1).

    Token format: opc_org.<token_id>.<secret>
    Usage: Authorization: Bearer opc_org.<token_id>.<secret>
    """

    def authenticate(self, request):
        org_token = authenticate_organization_token(request)
        if org_token is None:
            return None

        # Attach token metadata to the request
        bind_organization_token(request, org_token)

        return (org_token.created_by, None)
