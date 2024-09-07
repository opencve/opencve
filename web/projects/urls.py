from django.urls import path, register_converter

from opencve.utils import DateConverter
from projects.views import (
    NotificationCreateView,
    NotificationsView,
    NotificationDeleteView,
    NotificationUpdateView,
    ProjectCreateView,
    ProjectDeleteView,
    ProjectDetailView,
    ProjectEditView,
    ProjectsListView,
    ProjectVulnerabilitiesView,
    ReportsView,
    ReportView,
    SubscriptionsView,
)

register_converter(DateConverter, "date")

urlpatterns = [
    path("org/<org_name>/projects/", ProjectsListView.as_view(), name="list_projects"),
    path(
        "org/<org_name>/projects/add",
        ProjectCreateView.as_view(),
        name="create_project",
    ),
    path(
        "org/<org_name>/projects/<project_name>",
        ProjectDetailView.as_view(),
        name="project",
    ),
    path(
        "org/<org_name>/projects/<project_name>/edit",
        ProjectEditView.as_view(),
        name="edit_project",
    ),
    path(
        "org/<org_name>/projects/<project_name>/delete",
        ProjectDeleteView.as_view(),
        name="delete_project",
    ),
    path(
        "org/<org_name>/projects/<project_name>/notifications",
        NotificationsView.as_view(),
        name="notifications",
    ),
    path(
        "org/<org_name>/projects/<project_name>/notifications/add",
        NotificationCreateView.as_view(),
        name="create_notification",
    ),
    path(
        "org/<org_name>/projects/<project_name>/notifications/<notification>",
        NotificationUpdateView.as_view(),
        name="edit_notification",
    ),
    path(
        "org/<org_name>/projects/<project_name>/notifications/<notification>/delete",
        NotificationDeleteView.as_view(),
        name="delete_notification",
    ),
    path(
        "org/<org_name>/projects/<project_name>/reports",
        ReportsView.as_view(),
        name="reports",
    ),
    path(
        "org/<org_name>/projects/<project_name>/reports/<date:day>",
        ReportView.as_view(),
        name="report",
    ),
    path(
        "org/<org_name>/projects/<project_name>/subscriptions",
        SubscriptionsView.as_view(),
        name="subscriptions",
    ),
    path(
        "org/<org_name>/projects/<project_name>/vulnerabilities",
        ProjectVulnerabilitiesView.as_view(),
        name="project_vulnerabilities",
    ),
]
