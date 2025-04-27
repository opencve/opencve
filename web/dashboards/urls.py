from django.urls import path

from dashboards.views import (
    DashboardView,
    SaveDashboardView,
    LoadDashboardView,
    LoadWidgetConfigView,
    LoadWidgetDataView,
    RenderWidgetDataView,
)

urlpatterns = [
    path("", DashboardView.as_view(), name="home"),
    path("ajax/load_dashboard", LoadDashboardView.as_view(), name="load_dashboard"),
    path("ajax/save_dashboard", SaveDashboardView.as_view(), name="save_dashboard"),
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
