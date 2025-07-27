from django.urls import path

from feeds.views import (
    FeedTokenListView,
    FeedTokenCreateView,
    FeedTokenDeleteView,
    UserFeed,
    ProjectFeed
)

app_name = 'feeds'

urlpatterns = [
    path("", FeedTokenListView.as_view(), name="feed_tokens"),
    path("create/", FeedTokenCreateView.as_view(), name="create_token"),
    path("delete/<uuid:token_id>/", FeedTokenDeleteView.as_view(), name="delete_token"),
    path("feed/<str:token>/", UserFeed(), name="user_feed"),
    path(
        "feed/<str:token>/<str:org_name>/<str:project_name>/",
        ProjectFeed(),
        name="project_feed"
    ),
]