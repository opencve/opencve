from django.urls import path

from onboarding.views import OnboardingFormView, SearchVendorsProductsView

urlpatterns = [
    path("onboarding/", OnboardingFormView.as_view(), name="onboarding"),
    path(
        "onboarding/search-vendors-products/",
        SearchVendorsProductsView.as_view(),
        name="onboarding_search_vendors_products",
    ),
]
