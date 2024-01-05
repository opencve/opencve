from django.contrib import admin
from django.urls import include, path
from rest_framework_nested import routers

from cves.resources import CveViewSet, CweViewSet, ProductViewSet, VendorViewSet
from projects.resources import ProjectViewSet
from changes.resources import ChangeViewSet, ReportViewSet
from users.views import CustomLoginView, register


# = DONE =
# /cves
# /cves?vendor=x&product=x&cvss=x&search=x&cwe=x
# /cves/<id>
# /projects/
# /projects/<id>
# /projects/<id>/reports
# /projects/<id>/reports/<id>
# /changes/<id>
# /changes/<id>/events
# /vendors
# /vendors/<id>
# /vendors/<id>/products
# /vendors/<id>/products/<id>
# /cwes/
# /cwes/<id>

# API Router
router = routers.SimpleRouter()
router.register(r'cve', CveViewSet, basename="cve")
router.register(r'projects', ProjectViewSet, basename="project")
router.register(r'changes', ChangeViewSet, basename="change")
router.register(r'vendors', VendorViewSet, basename="vendor")
router.register(r'cwe', CweViewSet, basename="cwe")

projects_router = routers.NestedSimpleRouter(router, r'projects', lookup='project')
projects_router.register(r'reports', ReportViewSet, basename='project-reports')

changes_router = routers.NestedSimpleRouter(router, r'changes', lookup='change')
#changes_router.register(r'events', EventViewSet, basename='change-events')

vendors_router = routers.NestedSimpleRouter(router, r'vendors', lookup='vendor')
vendors_router.register(r'products', ProductViewSet, basename='vendor-products')


urlpatterns = [
    path("__debug__/", include("debug_toolbar.urls")),
    path("", include("changes.urls")),
    path("", include("cves.urls")),
    path("", include("organizations.urls")),
    path("", include("projects.urls")),
    path("register/", register, name="register"),
    path("account/", include("users.urls")),
    path("login/", CustomLoginView.as_view(), name="login"),
    path("admin/", admin.site.urls),
    path('hijack/', include('hijack.urls')),

    # API routes
    path("api/", include(router.urls)),
    path("api/", include(projects_router.urls)),
    path("api/", include(changes_router.urls)),
    path("api/", include(vendors_router.urls)),
]
