from django.contrib import admin
from django.urls import include, path

from users.views import CustomLoginView, register

urlpatterns = [
    path("__debug__/", include("debug_toolbar.urls")),
    path("", include("changes.urls")),
    path("", include("cves.urls")),
    path("", include("projects.urls")),
    path("register/", register, name="register"),
    path("account/", include("users.urls")),
    path("login/", CustomLoginView.as_view(), name="login"),
    path("admin/", admin.site.urls),
    path('hijack/', include('hijack.urls')),
]
