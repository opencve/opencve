from django.contrib.auth import views
from django.urls import path

from users.views import (
    CustomPasswordResetConfirmView,
    CustomPasswordResetView,
    SettingsPasswordView,
    SettingsProfileView,
    TagCreateView,
    TagDeleteView,
    TagEditView,
    TagsListView,
    account,
)

urlpatterns = [
    path("", account, name="account"),
    # Tags
    path("tags/", TagsListView.as_view(), name="tags"),
    path("tags/add", TagCreateView.as_view(), name="create_tag"),
    path("tags/<name>/edit", TagEditView.as_view(), name="edit_tag"),
    path("tags/<name>/delete", TagDeleteView.as_view(), name="delete_tag"),
    path("login/", views.LoginView.as_view(), name="login"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
    path("password/", SettingsPasswordView.as_view(), name="settings_password"),
    path("password_reset/", CustomPasswordResetView.as_view(), name="password_reset"),
    path("profile/", SettingsProfileView.as_view(), name="settings_profile"),
    path(
        "reset/<uidb64>/<token>/",
        CustomPasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),
]
