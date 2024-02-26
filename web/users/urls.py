from django.urls import path

from users.views import (SettingsPasswordView, SettingsProfileView,
                         TagCreateView, TagDeleteView, TagEditView,
                         TagsListView)

urlpatterns = [
    path("tags/", TagsListView.as_view(), name="tags"),
    path("tags/add", TagCreateView.as_view(), name="create_tag"),
    path("tags/<name>/edit", TagEditView.as_view(), name="edit_tag"),
    path("tags/<name>/delete", TagDeleteView.as_view(), name="delete_tag"),
    path("password/", SettingsPasswordView.as_view(), name="settings_password"),
    path("profile/", SettingsProfileView.as_view(), name="settings_profile"),
]
