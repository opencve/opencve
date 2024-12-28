from django.urls import path

from cves.views import (
    CveDetailView,
    CveListView,
    StatisticsView,
    SubscriptionView,
    VendorListView,
    WeaknessListView,
)

urlpatterns = [
    path("cve/", CveListView.as_view(), name="cves"),
    path("cve/<cve_id>", CveDetailView.as_view(), name="cve"),
    path("weaknesses/", WeaknessListView.as_view(), name="weaknesses"),
    path("vendors/", VendorListView.as_view(), name="vendors"),
    path("vendors/subscribe", SubscriptionView.as_view(), name="subscribe"),
    path("statistics", StatisticsView.as_view(), name="statistics"),
]
