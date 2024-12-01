from django.conf import settings
from django.shortcuts import redirect
from django.urls import resolve


class OnboardingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not request.user.is_authenticated:
            return self.get_response(request)

        organizations = request.user.list_organizations()
        if not organizations and settings.ENABLE_ONBOARDING:

            current_view_name = resolve(request.path).view_name
            if (
                not request.path.startswith("/api")
                and not request.path.startswith("/settings")
                and current_view_name not in ["onboarding", "hijack:release"]
            ):
                return redirect("onboarding")

        return self.get_response(request)
