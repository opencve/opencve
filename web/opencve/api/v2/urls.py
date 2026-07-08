from django.urls import path
from rest_framework_nested import routers

from opencve.api.v2.viewsets.catalog import (
    CveViewSet,
    ProductCveViewSet,
    ProductViewSet,
    VendorCveViewSet,
    VendorViewSet,
    WeaknessCveViewSet,
    WeaknessViewSet,
)
from opencve.api.v2.viewsets.organizations import (
    OrganizationAuditLogViewSet,
    OrganizationMemberViewSet,
    OrganizationViewSet,
)
from opencve.api.v2.viewsets.projects import (
    AutomationExecutionViewSet,
    AutomationViewSet,
    NotificationViewSet,
    ProjectCveDetailViewSet,
    ProjectCveViewSet,
    ProjectSubscriptionViewSet,
    ProjectViewSet,
    ReportViewSet,
)

router = routers.SimpleRouter(trailing_slash=False)
router.register(r"cves", CveViewSet, basename="v2-cve")
router.register(r"weaknesses", WeaknessViewSet, basename="v2-weakness")
router.register(r"vendors", VendorViewSet, basename="v2-vendor")
router.register(r"organizations", OrganizationViewSet, basename="v2-organization")

vendors_router = routers.NestedSimpleRouter(router, r"vendors", lookup="vendor")
vendors_router.register(r"products", ProductViewSet, basename="v2-vendor-product")

organizations_router = routers.NestedSimpleRouter(
    router, r"organizations", lookup="organization"
)
organizations_router.register(
    r"members", OrganizationMemberViewSet, basename="v2-organization-member"
)
organizations_router.register(
    r"audit-logs", OrganizationAuditLogViewSet, basename="v2-organization-audit-log"
)
organizations_router.register(
    r"projects", ProjectViewSet, basename="v2-organization-project"
)

projects_router = routers.NestedSimpleRouter(
    organizations_router, r"projects", lookup="project"
)
projects_router.register(
    r"notifications", NotificationViewSet, basename="v2-project-notification"
)
projects_router.register(
    r"automations", AutomationViewSet, basename="v2-project-automation"
)
projects_router.register(r"reports", ReportViewSet, basename="v2-project-report")

automations_router = routers.NestedSimpleRouter(
    projects_router, r"automations", lookup="automation"
)
automations_router.register(
    r"executions",
    AutomationExecutionViewSet,
    basename="v2-project-automation-execution",
)

urlpatterns = (
    router.urls
    + vendors_router.urls
    + organizations_router.urls
    + projects_router.urls
    + automations_router.urls
    + [
        path(
            "weaknesses/<str:cwe_id>/cves",
            WeaknessCveViewSet.as_view({"get": "list"}),
            name="v2-weakness-cves",
        ),
        path(
            "vendors/<str:vendor_name>/cves",
            VendorCveViewSet.as_view({"get": "list"}),
            name="v2-vendor-cves",
        ),
        path(
            "vendors/<str:vendor_name>/products/<str:product_name>/cves",
            ProductCveViewSet.as_view({"get": "list"}),
            name="v2-product-cves",
        ),
        path(
            "cves/<str:cve_id>/changes/<uuid:change_id>",
            CveViewSet.as_view({"get": "change_detail"}),
            name="v2-cve-change-detail",
        ),
        path(
            "organizations/<str:organization_name>/projects/<str:project_name>/subscriptions",
            ProjectSubscriptionViewSet.as_view(
                {
                    "get": "list",
                    "post": "create",
                    "put": "update",
                    "delete": "destroy",
                }
            ),
            name="v2-project-subscriptions",
        ),
        path(
            "organizations/<str:organization_name>/projects/<str:project_name>/cves",
            ProjectCveViewSet.as_view({"get": "list"}),
            name="v2-organization-project-cves",
        ),
        path(
            "organizations/<str:organization_name>/projects/<str:project_name>/cves/<str:cve_id>",
            ProjectCveDetailViewSet.as_view(
                {"get": "retrieve", "patch": "partial_update"}
            ),
            name="v2-organization-project-cve-detail",
        ),
    ]
)
