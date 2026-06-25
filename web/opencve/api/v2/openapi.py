from drf_spectacular.utils import OpenApiExample

from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView


PROJECT_CREATE_EXAMPLE = OpenApiExample(
    "Create project",
    value={
        "name": "production",
        "description": "Production infrastructure monitoring",
        "active": True,
    },
    request_only=True,
)

PROJECT_UPDATE_EXAMPLE = OpenApiExample(
    "Update project",
    value={"description": "Updated description", "active": False},
    request_only=True,
)

ORGANIZATION_CREATE_EXAMPLE = OpenApiExample(
    "Create organization",
    value={"name": "acme-corp"},
    request_only=True,
)

ORGANIZATION_UPDATE_EXAMPLE = OpenApiExample(
    "Rename organization",
    value={"name": "acme-security"},
    request_only=True,
)


def preprocessing_filter_v2(endpoints):
    return [endpoint for endpoint in endpoints if endpoint[0].startswith("/api/v2/")]


class V2SpectacularAPIView(SpectacularAPIView):
    custom_settings = {
        "TITLE": "OpenCVE API v2",
        "VERSION": "2026-06-24",
        "DESCRIPTION": (
            "OpenCVE REST API v2.\n\n"
            "All endpoints live under `/api/v2/` and require a Bearer organization "
            "API token (`ocve_<token_id>.<secret>`)."
        ),
        "PREPROCESSING_HOOKS": [
            "opencve.api.v2.openapi.preprocessing_filter_v2",
        ],
    }


class V2SpectacularSwaggerView(SpectacularSwaggerView):
    pass
