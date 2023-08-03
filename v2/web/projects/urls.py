from django.urls import path, register_converter

from opencve.utils import DateConverter
from projects.views import (
    NotificationCreateView,
    NotificationsView,
    NotificationUpdateView,
    ProjectDetailView,
    ReportsView,
    ReportView,
    SubscriptionsView,
)

register_converter(DateConverter, "date")

urlpatterns = [
    path("projects/<name>", ProjectDetailView.as_view(), name="project"),
    path(
        "projects/<name>/notifications", NotificationsView.as_view(), name="notifications"
    ),
    path(
        "projects/<name>/notifications/add",
        NotificationCreateView.as_view(),
        name="create_notification",
    ),
    path(
        "projects/<name>/notifications/<notification>",
        NotificationUpdateView.as_view(),
        name="edit_notification",
    ),
    path("projects/<name>/reports", ReportsView.as_view(), name="reports"),
    path("projects/<name>/reports/<date:day>", ReportView.as_view(), name="report"),
    path(
        "projects/<name>/subscriptions",
        SubscriptionsView.as_view(),
        name="subscriptions",
    ),
]
