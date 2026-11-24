from django.urls import path

from cves.views import (
    CveCsvExportView,
    CveDetailView,
    CveListPageView,
    CveListView,
    StatisticsView,
    SubscriptionView,
    VendorListLoadMoreView,
    VendorListView,
    WeaknessListPageView,
    WeaknessListView,
)

urlpatterns = [
    path("cve/export/csv", CveCsvExportView.as_view(), name="cves_export_csv"),
    path("cve/page/", CveListPageView.as_view(), name="cves_page"),
    path("cve/", CveListView.as_view(), name="cves"),
    path("cve/<cve_id>", CveDetailView.as_view(), name="cve"),
    path("weaknesses/page/", WeaknessListPageView.as_view(), name="weaknesses_page"),
    path("weaknesses/", WeaknessListView.as_view(), name="weaknesses"),
    path("vendors/", VendorListView.as_view(), name="vendors"),
    path(
        "vendors/load-more/<str:list_type>/",
        VendorListLoadMoreView.as_view(),
        name="vendors_load_more",
    ),
    path("vendors/subscribe", SubscriptionView.as_view(), name="subscribe"),
    path("statistics", StatisticsView.as_view(), name="statistics"),
]
