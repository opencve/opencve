from django.urls import path

from views.views import (
    ViewCreateView,
    ViewDeleteView,
    ViewListView,
    ViewUpdateView,
)

urlpatterns = [
    path("org/<str:org_name>/views/", ViewListView.as_view(), name="list_views"),
    path("org/<str:org_name>/views/add/", ViewCreateView.as_view(), name="create_view"),
    path(
        "org/<str:org_name>/views/<str:view_name>/edit/",
        ViewUpdateView.as_view(),
        name="update_view",
    ),
    path(
        "org/<str:org_name>/views/<str:view_name>/delete/",
        ViewDeleteView.as_view(),
        name="delete_view",
    ),
]
