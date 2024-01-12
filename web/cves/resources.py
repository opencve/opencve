from rest_framework import permissions, viewsets

from cves.models import Cve, Product, Vendor, Weakness
from cves.serializers import CveListSerializer, CveDetailSerializer, CweListSerializer, ProductListSerializer, VendorListSerializer
from cves.views import list_filtered_cves


class CveViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = CveListSerializer
    queryset = Cve.objects.order_by("-updated_at").all()
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "cve_id"

    serializer_classes = {
        "list": CveListSerializer,
        "retrieve": CveDetailSerializer,
    }

    def get_queryset(self):
        if self.action == "retrieve":
            return self.queryset
        return list_filtered_cves(self.request)

    def get_serializer_class(self):
        return self.serializer_classes.get(self.action, self.serializer_class)


class WeaknessViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = CweListSerializer
    queryset = Weakness.objects.all().order_by("cwe_id")
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "cwe_id"


class VendorViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = VendorListSerializer
    permission_classes = (permissions.IsAuthenticated,)
    queryset = Vendor.objects.order_by("name").all()


class ProductViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ProductListSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def get_queryset(self):
        return Product.objects.filter(
            vendor_id=self.kwargs['vendor_pk']
        ).order_by("name").all()
