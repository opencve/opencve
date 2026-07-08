from django.shortcuts import get_object_or_404
from rest_framework.exceptions import NotFound
from rest_framework.parsers import JSONParser

from opencve.api.v2.authentication import OrganizationTokenAuthentication
from opencve.api.v2.pagination import PageNumberPagination
from opencve.api.v2.permissions import IsOrganizationTokenAuthenticated, RequiresScope
from organizations.models import Organization
from projects.models import Project


class ViewSetMixin:
    authentication_classes = [OrganizationTokenAuthentication]
    permission_classes = [IsOrganizationTokenAuthenticated]
    parser_classes = [JSONParser]
    pagination_class = PageNumberPagination
    scope_map: dict = {}

    @property
    def is_schema_generation(self):
        return getattr(self, "swagger_fake_view", False)

    def get_permissions(self):
        # Map the current DRF action to an APIScope
        scope = self.scope_map.get(self.action)
        return [IsOrganizationTokenAuthenticated(), RequiresScope(scope)]


class OrganizationScopedMixin:
    organization_lookup_kwarg = "organization_name"

    def get_organization(self):
        """Get the organization for the current request"""
        if hasattr(self, "organization"):
            return self.organization

        if self.is_schema_generation:
            self.organization = Organization(
                name=self.kwargs.get(self.organization_lookup_kwarg, "")
            )
            return self.organization

        # Check if the organization name matches the token organization
        org_name = self.kwargs[self.organization_lookup_kwarg]
        token_org = self.request.authenticated_organization
        if token_org.name != org_name:
            raise NotFound()

        self.organization = token_org
        return self.organization


class ProjectScopedMixin(OrganizationScopedMixin):
    project_lookup_kwarg = "project_name"

    def get_project(self):
        """Get the project for the current request"""
        if hasattr(self, "project"):
            return self.project

        if self.is_schema_generation:
            organization = self.get_organization()
            self.project = Project(
                organization=organization,
                name=self.kwargs.get(self.project_lookup_kwarg, ""),
            )
            return self.project

        # Check if the project exists in the specified organization
        organization = self.get_organization()
        project_name = self.kwargs[self.project_lookup_kwarg]
        self.project = get_object_or_404(
            Project, organization=organization, name=project_name
        )

        if not self.project.active:
            raise NotFound()

        return self.project
