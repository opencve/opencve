from rest_framework import permissions, viewsets

from projects.models import Project
from projects.serializers import ProjectSerializer, ProjectDetailSerializer


class ProjectViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ProjectSerializer
    permission_classes = (permissions.IsAuthenticated,)

    serializer_classes = {
        "list": ProjectSerializer,
        "retrieve": ProjectDetailSerializer,
    }

    def get_queryset(self):
        return Project.objects.filter(user=self.request.user).order_by("name").all()

    def get_serializer_class(self):
        return self.serializer_classes.get(self.action, self.serializer_class)
