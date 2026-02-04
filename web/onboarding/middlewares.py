from django.conf import settings
from django.shortcuts import redirect
from django.urls import resolve
from django.urls.exceptions import Resolver404


# View names that must NOT trigger a redirect to onboarding
ONBOARDING_ALLOWED_VIEW_NAMES = frozenset(
    [
        "onboarding",
        "onboarding_search_vendors_products",
        "hijack:release",
        "accept_organization_invitation",
    ]
)


class OnboardingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not request.user.is_authenticated:
            return self.get_response(request)

        organizations = request.user.list_organizations()
        if not organizations and settings.ENABLE_ONBOARDING:
            # Allow Debug Toolbar (and similar dev endpoints) so they don't get redirected
            if request.path.startswith("/__debug__/"):
                return self.get_response(request)

            try:
                current_view_name = resolve(request.path).view_name
            except Resolver404:
                current_view_name = None

            if current_view_name in ONBOARDING_ALLOWED_VIEW_NAMES:
                return self.get_response(request)

            if request.path.startswith("/api") or request.path.startswith("/settings"):
                return self.get_response(request)

            return redirect("onboarding")

        return self.get_response(request)
