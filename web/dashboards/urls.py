from django.urls import path

from dashboards.views import (
    CreateDashboardView,
    DashboardView,
    DeleteDashboardView,
    LoadDashboardView,
    LoadWidgetConfigView,
    LoadWidgetDataView,
    RenderWidgetDataView,
    SaveDashboardView,
    UpdateDashboardView,
)

urlpatterns = [
    path("", DashboardView.as_view(), name="home"),
    path("ajax/load_dashboard", LoadDashboardView.as_view(), name="load_dashboard"),
    path("ajax/save_dashboard", SaveDashboardView.as_view(), name="save_dashboard"),
    path(
        "ajax/create_dashboard",
        CreateDashboardView.as_view(),
        name="create_dashboard",
    ),
    path(
        "ajax/update_dashboard",
        UpdateDashboardView.as_view(),
        name="update_dashboard",
    ),
    path(
        "ajax/delete_dashboard",
        DeleteDashboardView.as_view(),
        name="delete_dashboard",
    ),
    path(
        "ajax/load_widget_config/<widget_type>",
        LoadWidgetConfigView.as_view(),
        name="load_widget_config",
    ),
    path(
        "ajax/load_widget_data/<widget_id>",
        LoadWidgetDataView.as_view(),
        name="load_widget_data",
    ),
    path(
        "ajax/render_widget_data/<widget_type>",
        RenderWidgetDataView.as_view(),
        name="render_widget_data",
    ),
]
