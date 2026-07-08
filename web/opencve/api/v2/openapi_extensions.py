from drf_spectacular.extensions import OpenApiAuthenticationExtension


class OrganizationTokenAuthenticationExtension(OpenApiAuthenticationExtension):
    target_class = "opencve.api.v2.authentication.OrganizationTokenAuthentication"
    name = "OrganizationBearerAuth"

    def get_security_definition(self, auto_schema):
        return {
            "type": "http",
            "scheme": "bearer",
            "description": (
                "Organization API token.\n\n"
                "Format: `opc_org.<token_id>.<secret>`\n\n"
                "Example header: `Authorization: Bearer opc_org.abc123xyz.xYz...`"
            ),
        }
