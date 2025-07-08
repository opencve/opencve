from django.urls import path

from users.views import (
    SettingsPasswordView,
    SettingsProfileView,
    SettingsAccountView,
    SettingsDeleteAccountView,
    TagCreateView,
    TagDeleteView,
    TagEditView,
    TagsListView,
    CustomConnectionView,
)

urlpatterns = [
    path("tags/", TagsListView.as_view(), name="tags"),
    path("tags/add", TagCreateView.as_view(), name="create_tag"),
    path("tags/<name>/edit", TagEditView.as_view(), name="edit_tag"),
    path("tags/<name>/delete", TagDeleteView.as_view(), name="delete_tag"),
    path("password/", SettingsPasswordView.as_view(), name="settings_password"),
    path("profile/", SettingsProfileView.as_view(), name="settings_profile"),
    path("social", CustomConnectionView.as_view(), name="settings_social"),
    path("account/", SettingsAccountView.as_view(), name="settings_account"),
    path("account/delete", SettingsDeleteAccountView.as_view(), name="delete_account"),
]
