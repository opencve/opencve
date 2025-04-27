from django.urls import path

from changes.views import ChangeDetailView, ChangeListView

urlpatterns = [
    path("activity", ChangeListView.as_view(), name="activity"),
    path(
        "cve/<slug:cve_id>/changes/<slug:id>", ChangeDetailView.as_view(), name="change"
    ),
]
