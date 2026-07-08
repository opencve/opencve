from rest_framework import authentication

from opencve.api.tokens import authenticate_organization_token, bind_organization_token


class OrganizationTokenAuthentication(authentication.BaseAuthentication):
    """Authentication for organization tokens"""

    def authenticate(self, request):
        org_token = authenticate_organization_token(request)
        if org_token is None:
            return None

        # Attach token metadata to the request
        bind_organization_token(request, org_token)
        request.organization_token = org_token
        request.api_actor = org_token.created_by

        return (org_token.created_by, org_token)

    def authenticate_header(self, request):
        return "Bearer"
