from django.urls import path, register_converter

from opencve.utils import DateConverter
from projects.views import (
    NotificationCreateView,
    NotificationsView,
    NotificationUpdateView,
    ProjectDetailView,
    ProjectCreateView,
    ProjectDeleteView,
    ProjectEditView,
    ProjectsListView,
    ProjectVulnerabilitiesView,
    ReportsView,
    ReportView,
    SubscriptionsView,
)

register_converter(DateConverter, "date")

urlpatterns = [
    # Projects
    path("org/<orgname>/projects/", ProjectsListView.as_view(), name="list_projects"),
    path(
        "org/<orgname>/projects/add", ProjectCreateView.as_view(), name="create_project"
    ),
    path("org/<orgname>/projects/<name>", ProjectDetailView.as_view(), name="project"),
    path(
        "org/<orgname>/projects/<name>/edit",
        ProjectEditView.as_view(),
        name="edit_project",
    ),
    path(
        "org/<orgname>/projects/<name>/delete",
        ProjectDeleteView.as_view(),
        name="delete_project",
    ),
    path(
        "org/<orgname>/projects/<name>/vulnerabilities",
        ProjectVulnerabilitiesView.as_view(),
        name="project_vulnerabilities",
    ),
    path(
        "org/<orgname>/projects/<name>/notifications",
        NotificationsView.as_view(),
        name="notifications",
    ),
    path(
        "org/<orgname>/projects/<name>/notifications/add",
        NotificationCreateView.as_view(),
        name="create_notification",
    ),
    path(
        "org/<orgname>/projects/<name>/notifications/<notification>",
        NotificationUpdateView.as_view(),
        name="edit_notification",
    ),
    path(
        "org/<orgname>/projects/<name>/reports", ReportsView.as_view(), name="reports"
    ),
    path(
        "org/<orgname>/projects/<name>/reports/<date:day>",
        ReportView.as_view(),
        name="report",
    ),
    path(
        "org/<orgname>/projects/<name>/subscriptions",
        SubscriptionsView.as_view(),
        name="subscriptions",
    ),
]
