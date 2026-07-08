from django.http import Http404
from rest_framework.exceptions import (
    AuthenticationFailed,
    NotFound,
    PermissionDenied,
    ValidationError,
)
from opencve.api.v2.permissions import MissingScope
from rest_framework.views import exception_handler as drf_exception_handler


def exception_handler(exc, context):
    """Format DRF exceptions as {"error": {"code", "message", ...}} for API clients.

    Expected codes: invalid_token, not_found, missing_scope, read_only_token,
    validation_error, permission_denied.
    """
    if isinstance(exc, Http404):
        exc = NotFound()

    # Handle DRF exceptions
    response = drf_exception_handler(exc, context)
    if response is None:
        return response

    # Add default code to the error response
    code = getattr(exc, "default_code", "error")
    if isinstance(exc, AuthenticationFailed):
        code = "invalid_token"
    elif isinstance(exc, NotFound):
        code = "not_found"
    elif isinstance(exc, PermissionDenied):
        code = getattr(exc, "default_code", "permission_denied")
        if isinstance(exc, MissingScope) or code == "missing_scope":
            code = "missing_scope"
    elif isinstance(exc, ValidationError):
        code = "validation_error"
    error = {"code": code, "message": _error_message(exc)}

    # Add required scope to the error response
    if hasattr(exc, "required_scope") and exc.required_scope:
        error["required_scope"] = exc.required_scope

    # Add details to the error response
    if isinstance(getattr(exc, "detail", None), dict):
        error["details"] = exc.detail
        error["message"] = "Validation error."

    response.data = {"error": error}
    return response


def _error_message(exc):
    """Get the error message from the exception"""
    detail = getattr(exc, "detail", None)

    if detail is None:
        if exc.args:
            return str(exc.args[0])
        return str(exc)

    if isinstance(detail, list):
        return " ".join(str(item) for item in detail)

    if isinstance(detail, dict):
        return "Validation error."

    return str(detail)
