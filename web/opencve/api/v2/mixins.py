from django.shortcuts import get_object_or_404
from rest_framework.exceptions import NotFound

from opencve.api.v2.authentication import V2OrganizationTokenAuthentication
from opencve.api.v2.pagination import V2PageNumberPagination
from opencve.api.v2.permissions import IsV2OrganizationTokenAuthenticated, RequiresScope
from opencve.api.v2.throttling import V2OrganizationTokenRateThrottle
from projects.models import Project


class V2ViewSetMixin:
    authentication_classes = [V2OrganizationTokenAuthentication]
    permission_classes = [IsV2OrganizationTokenAuthenticated]
    pagination_class = V2PageNumberPagination
    throttle_classes = [V2OrganizationTokenRateThrottle]
    scope_map: dict = {}

    def get_permissions(self):
        scope = self.scope_map.get(self.action)
        return [IsV2OrganizationTokenAuthenticated(), RequiresScope(scope)]


class V2OrganizationScopedMixin:
    organization_lookup_kwarg = "organization_name"

    def get_organization(self):
        if hasattr(self, "organization"):
            return self.organization
        org_name = self.kwargs[self.organization_lookup_kwarg]
        token_org = self.request.authenticated_organization
        if token_org.name != org_name:
            raise NotFound()
        self.organization = token_org
        return self.organization


class V2ProjectScopedMixin(V2OrganizationScopedMixin):
    project_lookup_kwarg = "project_name"

    def get_project(self):
        if hasattr(self, "project"):
            return self.project
        organization = self.get_organization()
        project_name = self.kwargs[self.project_lookup_kwarg]
        self.project = get_object_or_404(
            Project, organization=organization, name=project_name
        )
        return self.project


class V2APIViewMixin:
    authentication_classes = V2ViewSetMixin.authentication_classes
    permission_classes = V2ViewSetMixin.permission_classes
    throttle_classes = V2ViewSetMixin.throttle_classes
    scope_map: dict = {}

    def get_permissions(self):
        scope = self.scope_map.get(self.request.method.lower())
        return [
            IsV2OrganizationTokenAuthenticated(),
            RequiresScope(scope),
        ]
