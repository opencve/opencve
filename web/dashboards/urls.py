from django.urls import path

from dashboards.views import DashboardView, save_dashboard, load_dashboard

urlpatterns = [
    path("", DashboardView.as_view(), name="home"),
    path("ajax/save_dashboard", save_dashboard, name="save_dashboard"),
    path("ajax/load_dashboard", load_dashboard, name="load_dashboard"),
]
