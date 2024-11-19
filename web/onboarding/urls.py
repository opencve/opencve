from django.urls import path, re_path

from onboarding.views import OnboardingFormView

urlpatterns = [
    path("onboarding/", OnboardingFormView.as_view(), name="onboarding"),
]
