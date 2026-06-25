from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView


def preprocessing_filter_v1(endpoints):
    return [
        endpoint for endpoint in endpoints if not endpoint[0].startswith("/api/v2/")
    ]


class V1SpectacularAPIView(SpectacularAPIView):
    custom_settings = {
        "TITLE": "OpenCVE API v1",
        "VERSION": "2024-01-01",
        "DESCRIPTION": (
            "OpenCVE REST API v1 (read-only).\n\n"
            "Endpoints under `/api/` support Basic Auth or organization Bearer tokens. "
            "Write operations are available in v2 at `/api/v2/`."
        ),
        "PREPROCESSING_HOOKS": [
            "opencve.api.openapi.v1.preprocessing_filter_v1",
        ],
    }


class V1SpectacularSwaggerView(SpectacularSwaggerView):
    pass
