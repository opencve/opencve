from rest_framework.throttling import SimpleRateThrottle


class V2OrganizationTokenRateThrottle(SimpleRateThrottle):
    scope = "org_token"

    def get_cache_key(self, request, view):
        token = getattr(request, "organization_token", None)
        if not token:
            return None
        scope = (
            "org_token_write"
            if request.method not in ("GET", "HEAD", "OPTIONS")
            else "org_token"
        )
        return self.cache_format % {"scope": scope, "ident": token.token_id}

    def allow_request(self, request, view):
        self.rate = self.get_rate()
        self.num_requests, self.duration = self.parse_rate(self.rate)
        return super().allow_request(request, view)

    def get_rate(self):
        if self.scope == "org_token_write":
            return "500/hour"
        return "2000/hour"
