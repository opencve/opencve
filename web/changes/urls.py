from django.urls import path

from changes.views import ChangeDetailView, ChangeListView

urlpatterns = [
    path("", ChangeListView.as_view(), name="home"),
    path(
        "cve/<slug:cve_id>/changes/<slug:id>", ChangeDetailView.as_view(), name="change"
    ),
]
