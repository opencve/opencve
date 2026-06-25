from rest_framework.throttling import (
    AnonRateThrottle,
    SimpleRateThrottle,
    UserRateThrottle,
)


class OrganizationTokenRateThrottle(SimpleRateThrottle):
    scope = "org_token"

    def get_cache_key(self, request, view):
        api_token = getattr(request, "api_token", None)
        if not api_token:
            return None
        scope = (
            "org_token_write"
            if request.method not in ("GET", "HEAD", "OPTIONS")
            else "org_token"
        )
        return self.cache_format % {"scope": scope, "ident": api_token.token_id}

    def allow_request(self, request, view):
        self.rate = self.get_rate()
        self.num_requests, self.duration = self.parse_rate(self.rate)
        return super().allow_request(request, view)

    def get_rate(self):
        if self.scope == "org_token_write":
            return "500/hour"
        return "2000/hour"


__all__ = [
    "AnonRateThrottle",
    "UserRateThrottle",
    "OrganizationTokenRateThrottle",
]
