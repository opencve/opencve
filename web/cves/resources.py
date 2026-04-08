from django.contrib.auth.models import AnonymousUser
from django.shortcuts import get_object_or_404
from rest_framework import mixins, permissions, viewsets, filters

from cves.constants import PRODUCT_SEPARATOR
from cves.models import Cve, Product, Vendor, Weakness
from cves.serializers import (
    CveDetailSerializer,
    CveListSerializer,
    ProductListSerializer,
    VendorListSerializer,
    WeaknessListSerializer,
)
from cves.utils import list_filtered_cves


class CveViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = CveListSerializer
    queryset = Cve.objects.order_by("-updated_at").all()
    lookup_field = "cve_id"

    serializer_classes = {
        "list": CveListSerializer,
        "retrieve": CveDetailSerializer,
    }

    def get_queryset(self):
        if self.action == "retrieve":
            return self.queryset

        # For organization tokens, use AnonymousUser to avoid tag filtering
        user = getattr(self.request, "api_token", None)
        if user:
            user = AnonymousUser()
        else:
            user = self.request.user
        return list_filtered_cves(self.request.GET, user)

    def get_serializer_class(self):
        return self.serializer_classes.get(self.action, self.serializer_class)


class WeaknessViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = WeaknessListSerializer
    queryset = Weakness.objects.all().order_by("cwe_id")
    lookup_field = "cwe_id"


class VendorViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = VendorListSerializer
    queryset = Vendor.objects.order_by("name").all()
    lookup_field = "name"
    lookup_url_kwarg = "name"
    filter_backends = [filters.SearchFilter]
    search_fields = ["name"]


class VendorCveViewSet(viewsets.GenericViewSet, mixins.ListModelMixin):
    serializer_class = CveListSerializer

    def get_queryset(self):
        vendor = get_object_or_404(Vendor, name=self.kwargs["vendor_name"])
        return (
            Cve.objects.order_by("-updated_at")
            .filter(vendors__contains=vendor.name)
            .all()
        )


class ProductViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ProductListSerializer
    lookup_field = "name"
    lookup_url_kwarg = "name"
    filter_backends = [filters.SearchFilter]
    search_fields = ["name"]

    def get_queryset(self):
        vendor = get_object_or_404(Vendor, name=self.kwargs["vendor_name"])
        return Product.objects.filter(vendor=vendor).order_by("name").all()


class ProductCveViewSet(viewsets.GenericViewSet, mixins.ListModelMixin):
    serializer_class = CveListSerializer

    def get_queryset(self):
        vendor = get_object_or_404(Vendor, name=self.kwargs["vendor_name"])
        product = get_object_or_404(
            Product, vendor=vendor, name=self.kwargs["product_name"]
        )
        return (
            Cve.objects.order_by("-updated_at")
            .filter(vendors__contains=f"{vendor}{PRODUCT_SEPARATOR}{product}")
            .all()
        )


class WeaknessCveViewSet(viewsets.GenericViewSet, mixins.ListModelMixin):
    serializer_class = CveListSerializer

    def get_queryset(self):
        weakness = get_object_or_404(Weakness, cwe_id=self.kwargs["weakness_cwe_id"])
        return (
            Cve.objects.order_by("-updated_at")
            .filter(weaknesses__contains=weakness.cwe_id)
            .all()
        )
