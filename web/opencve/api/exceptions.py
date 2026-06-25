from rest_framework.exceptions import APIException


class InsufficientScope(APIException):
    status_code = 403
    default_code = "insufficient_scope"
    default_detail = "The token does not have the required scope for this operation."

    def __init__(self, required_scope=None, detail=None):
        if detail is None:
            detail = self.default_detail
        super().__init__(detail=detail)
        self.required_scope = required_scope


def api_exception_handler(exc, context):
    request = context.get("request")
    if request and request.path.startswith("/api/v2/"):
        from opencve.api.v2.exceptions import v2_exception_handler

        return v2_exception_handler(exc, context)

    from rest_framework.views import exception_handler

    return exception_handler(exc, context)
