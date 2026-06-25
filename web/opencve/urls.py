from django.contrib import admin
from django.urls import include, path
from opencve.api.openapi.v1 import V1SpectacularAPIView, V1SpectacularSwaggerView
from opencve.api.v2.openapi import V2SpectacularAPIView, V2SpectacularSwaggerView
from rest_framework_nested import routers

from cves.resources import (
    CveViewSet,
    ProductCveViewSet,
    ProductViewSet,
    VendorCveViewSet,
    VendorViewSet,
    WeaknessCveViewSet,
    WeaknessViewSet,
)
from organizations.resources import OrganizationViewSet
from projects.resources import ProjectCveViewSet, ProjectViewSet
from projects.views import NotificationConfirmView, NotificationUnsubscribeView
from users.views import CustomLoginView, CustomSignupView

# API Router
router = routers.SimpleRouter(trailing_slash=False)
router.register(r"cve", CveViewSet, basename="cve")

router.register(r"weaknesses", WeaknessViewSet, basename="weakness")
weaknesses_router = routers.NestedSimpleRouter(router, r"weaknesses", lookup="weakness")
weaknesses_router.register(r"cve", WeaknessCveViewSet, basename="weakness-cves")

router.register(r"organizations", OrganizationViewSet, basename="organization")
organizations_router = routers.NestedSimpleRouter(
    router, r"organizations", lookup="organization"
)
organizations_router.register(
    r"projects", ProjectViewSet, basename="organization-projects"
)

projects_cves_router = routers.NestedSimpleRouter(
    organizations_router, "projects", lookup="project"
)
projects_cves_router.register(
    r"cve", ProjectCveViewSet, basename="organization-projects-cves"
)

router.register(r"vendors", VendorViewSet, basename="vendor")
vendors_router = routers.NestedSimpleRouter(router, r"vendors", lookup="vendor")
vendors_router.register(r"products", ProductViewSet, basename="vendor-products")
vendors_router.register(r"cve", VendorCveViewSet, basename="vendor-cves")
products_cves_router = routers.NestedSimpleRouter(
    vendors_router, "products", lookup="product"
)
products_cves_router.register(f"cve", ProductCveViewSet, basename="product-cves")


urlpatterns = [
    path("__debug__/", include("debug_toolbar.urls")),
    path("", include("dashboards.urls")),
    path("", include("changes.urls")),
    path("", include("cves.urls")),
    path("", include("onboarding.urls")),
    path("", include("organizations.urls")),
    path("", include("projects.urls")),
    path("", include("views.urls")),
    path("", include("django_prometheus.urls")),
    path("settings/", include("allauth.urls")),
    path(r"login/", CustomLoginView.as_view(), name="account_login"),
    path(r"signup/", CustomSignupView.as_view(), name="account_signup"),
    path("settings/", include("users.urls")),
    path("admin/", admin.site.urls),
    path("hijack/", include("hijack.urls")),
    path(
        "notifications/confirm/<str:token>/",
        NotificationConfirmView.as_view(),
        name="notification_confirm",
    ),
    path(
        "notifications/unsubscribe/<str:token>/",
        NotificationUnsubscribeView.as_view(),
        name="notification_unsubscribe",
    ),
    # API routes (v1 — default without OpenCVE-Api-Version header)
    path("api/", include(router.urls)),
    path("api/", include(organizations_router.urls)),
    path("api/", include(projects_cves_router.urls)),
    path("api/", include(vendors_router.urls)),
    path("api/", include(products_cves_router.urls)),
    path("api/", include(weaknesses_router.urls)),
    path("api/v2/", include("opencve.api.v2.urls")),
    path("api/schema/", V1SpectacularAPIView.as_view(), name="api-schema"),
    path(
        "api/docs/",
        V1SpectacularSwaggerView.as_view(url_name="api-schema"),
        name="api-docs",
    ),
    path("api/v2/schema/", V2SpectacularAPIView.as_view(), name="api-v2-schema"),
    path(
        "api/v2/docs/",
        V2SpectacularSwaggerView.as_view(url_name="api-v2-schema"),
        name="api-v2-docs",
    ),
]

# Custom errors
handler404 = "cves.views.handle_page_not_found"
handler500 = "cves.views.handle_server_error"
