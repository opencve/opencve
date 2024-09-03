from django.urls import path

from cves.views import (
    CveDetailView,
    CveListView,
    SubscriptionView,
    VendorListView,
    WeaknessListView,
    ProductListView,
)

urlpatterns = [
    path("cve/", CveListView.as_view(), name="cves"),
    path("cve/<cve_id>", CveDetailView.as_view(), name="cve"),
    path("weaknesses/", WeaknessListView.as_view(), name="weaknesses"),
    path("vendors/", VendorListView.as_view(), name="vendors"),
    path("products/", ProductListView.as_view(), name="products"),
    path("subscribe/", SubscriptionView.as_view(), name="subscribe"),
]
