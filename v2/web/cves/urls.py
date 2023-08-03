from django.urls import path

from cves.views import CveDetailView, CveListView, CweListView, SubscriptionView, VendorListView

urlpatterns = [
    path("cve/", CveListView.as_view(), name="cves"),
    path("cve/<cve_id>", CveDetailView.as_view(), name="cve"),
    path("cwe/", CweListView.as_view(), name="cwes"),
    path("vendors/", VendorListView.as_view(), name="vendors"),
    path("vendors/subscribe", SubscriptionView.as_view(), name="subscribe"),
]
