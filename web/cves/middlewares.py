from django.http import Http404


class SanitizeInputMiddleware:
    """
    Middleware to sanitize input by rejecting requests containing NULL bytes.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Check for NULL bytes in GET, POST, and other input
        if self._contains_null_bytes(request.GET) or self._contains_null_bytes(
            request.POST
        ):
            raise Http404

        return self.get_response(request)

    @staticmethod
    def _contains_null_bytes(data):
        """
        Helper function to check for NULL bytes in request data.
        """
        for key, value in data.items():
            if "\x00" in key or "\x00" in value:
                return True
        return False
