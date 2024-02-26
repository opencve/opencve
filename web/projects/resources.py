from django.shortcuts import get_object_or_404
from rest_framework import mixins, permissions, viewsets

from cves.models import Cve
from cves.serializers import CveListSerializer
from organizations.models import Organization
from projects.models import Project
from projects.serializers import ProjectDetailSerializer, ProjectSerializer


class ProjectViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ProjectSerializer
    permission_classes = (permissions.IsAuthenticated,)
    lookup_field = "name"
    lookup_url_kwarg = "name"

    serializer_classes = {
        "list": ProjectSerializer,
        "retrieve": ProjectDetailSerializer,
    }

    def get_queryset(self):
        organization = get_object_or_404(
            Organization,
            members=self.request.user,
            name=self.kwargs["organization_name"],
        )
        return Project.objects.filter(organization=organization).order_by("name").all()

    def get_serializer_class(self):
        return self.serializer_classes.get(self.action, self.serializer_class)


class ProjectCveViewSet(viewsets.GenericViewSet, mixins.ListModelMixin):
    serializer_class = CveListSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def get_queryset(self):
        organization = get_object_or_404(
            Organization,
            members=self.request.user,
            name=self.kwargs["organization_name"],
        )
        project = get_object_or_404(
            Project, organization=organization, name=self.kwargs["project_name"]
        )

        vendors = project.subscriptions["vendors"] + project.subscriptions["products"]
        if not vendors:
            return Cve.objects.none()
        return (
            Cve.objects.order_by("-updated_at")
            .filter(vendors__has_any_keys=vendors)
            .all()
        )
