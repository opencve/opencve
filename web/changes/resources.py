from rest_framework import mixins, permissions, viewsets
from rest_framework.viewsets import GenericViewSet

from changes.models import Change, Report
from changes.serializers import ChangeSerializer, ReportSerializer, ReportDetailSerializer


class ChangeViewSet(mixins.RetrieveModelMixin, GenericViewSet):
    serializer_class = ChangeSerializer
    permission_classes = (permissions.IsAuthenticated,)
    queryset = Change.objects.order_by("-created_at").all()

    def get_queryset(self):
        return Event.objects.filter(
            change=self.kwargs["change_pk"]
        ).order_by("-created_at").all()

    def get_serializer_class(self):
        return self.serializer_classes.get(self.action, self.serializer_class)


class ReportViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ReportSerializer
    permission_classes = (permissions.IsAuthenticated,)

    serializer_classes = {
        "list": ReportSerializer,
        "retrieve": ReportDetailSerializer,
    }

    def get_queryset(self):
        return Report.objects.filter(
            project__user=self.request.user,
            project=self.kwargs['project_pk']
        ).order_by("-day").all()

    def get_serializer_class(self):
        return self.serializer_classes.get(self.action, self.serializer_class)
