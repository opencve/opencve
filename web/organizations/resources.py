from django.shortcuts import get_object_or_404
from rest_framework import permissions, viewsets

from organizations.models import Organization
from organizations.serializers import (
    OrganizationDetailSerializer,
    OrganizationSerializer,
)


class OrganizationViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = OrganizationSerializer
    permission_classes = (permissions.IsAuthenticated,)
    lookup_field = "name"
    lookup_url_kwarg = "name"
    serializer_classes = {
        "list": OrganizationSerializer,
        "retrieve": OrganizationDetailSerializer,
    }

    def get_queryset(self):
        return (
            Organization.objects.filter(members=self.request.user)
            .order_by("name")
            .all()
        )

    def get_serializer_class(self):
        return self.serializer_classes.get(self.action, self.serializer_class)
