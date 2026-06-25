from rest_framework.exceptions import AuthenticationFailed, PermissionDenied
from rest_framework.views import exception_handler


def v2_exception_handler(exc, context):
    response = exception_handler(exc, context)
    if response is None:
        return response
    code = getattr(exc, "default_code", "error")
    if isinstance(exc, AuthenticationFailed):
        code = "invalid_token"
    elif isinstance(exc, PermissionDenied):
        code = getattr(exc, "default_code", "permission_denied")
        if code == "permission_denied":
            code = "missing_scope"
    error = {"code": code, "message": _error_message(exc)}
    if hasattr(exc, "required_scope") and exc.required_scope:
        error["required_scope"] = exc.required_scope
    if isinstance(getattr(exc, "detail", None), dict):
        error["details"] = exc.detail
        error["message"] = "Validation error."
    response.data = {"error": error}
    return response


def _error_message(exc):
    detail = exc.detail
    if isinstance(detail, list):
        return " ".join(str(item) for item in detail)
    if isinstance(detail, dict):
        return "Validation error."
    return str(detail)
