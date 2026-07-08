from rest_framework.views import exception_handler as drf_exception_handler
from opencve.api.v2.exceptions import exception_handler as v2_exception_handler


def api_exception_handler(exc, context):
    """Route exception handling to the v2 formatter or default DRF responses."""
    request = context.get("request")

    if request and request.path.startswith("/api/v2/"):
        return v2_exception_handler(exc, context)

    return drf_exception_handler(exc, context)
