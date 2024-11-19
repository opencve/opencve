from django.conf import settings
from django.shortcuts import redirect
from django.urls import resolve

from organizations.models import Membership


class OnboardingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not request.user.is_authenticated:
            return self.get_response(request)

        # List all memberships associated to the user
        memberships = (
            Membership.objects.filter(
                user=request.user,
                role__in=[Membership.OWNER, Membership.MEMBER],
                date_joined__isnull=False,
            )
            .order_by("organization__name")
            .all()
        )
        organizations = [m.organization for m in memberships]

        if not organizations and settings.ENABLE_ONBOARDING:

            current_view_name = resolve(request.path).view_name
            if not request.path.startswith("/api") and current_view_name not in [
                "onboarding"
            ]:
                return redirect("onboarding")

        return self.get_response(request)
