import csv
import io

from django.contrib.auth.models import AnonymousUser
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from rest_framework import mixins, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response

from changes.models import Change
from cves.models import Cve, Product, Vendor, Weakness
from cves.search import BadQueryException, MaxFieldsExceededException, Search
from cves.utils import list_filtered_cves
from opencve.api.v2.mixins import V2ViewSetMixin
from opencve.api.v2.serializers import (
    ChangeDetailSerializerV2,
    ChangeListSerializerV2,
    CveDetailSerializerV2,
    CveListSerializerV2,
    WeaknessSerializerV2,
)


class CveViewSet(V2ViewSetMixin, viewsets.ReadOnlyModelViewSet):
    lookup_field = "cve_id"
    queryset = Cve.objects.order_by("-updated_at").all()
    scope_map = {
        # Global catalog: any valid organization token may read CVEs.
        "list": None,
        "retrieve": None,
        "changes": None,
        "change_detail": None,
    }

    def get_serializer_class(self):
        if self.action == "retrieve":
            return CveDetailSerializerV2
        return CveListSerializerV2

    def get_queryset(self):
        if self.action == "retrieve":
            return self.queryset
        q = self.request.query_params.get("q")
        if q:
            search = Search(q, request=self.request)
            if not search.validate_parsing():
                raise ValidationError({"q": str(search.error)})
            try:
                return search.query
            except (BadQueryException, MaxFieldsExceededException) as exc:
                raise ValidationError({"q": str(exc)}) from exc

        # Org tokens must not apply user-tag filters; not used for auth.
        return list_filtered_cves(self.request.query_params, AnonymousUser())

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        data = serializer.data
        includes = {
            item.strip() for item in request.query_params.get("include", "").split(",")
        }
        if "nvd_cpe_configurations" in includes:
            data["nvd_cpe_configurations"] = instance.nvd_json.get("configurations", [])
        if "references" in includes:
            data["references"] = instance.nvd_json.get("references", [])
        return Response(data)

    def list(self, request, *args, **kwargs):
        if request.query_params.get("format") == "csv":
            return self._csv_export()
        return super().list(request, *args, **kwargs)

    def _csv_export(self):
        queryset = self.filter_queryset(self.get_queryset())
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["cve_id", "title", "description", "updated_at"])
        for cve in queryset[:5000]:
            writer.writerow(
                [cve.cve_id, cve.title or "", cve.description or "", cve.updated_at]
            )
        response = HttpResponse(buffer.getvalue(), content_type="text/csv")
        response["Content-Disposition"] = 'attachment; filename="cves.csv"'
        return response

    @action(detail=True, methods=["get"], url_path="changes")
    def changes(self, request, cve_id=None):
        cve = self.get_object()
        changes = Change.objects.filter(cve=cve).order_by("-created_at")
        page = self.paginate_queryset(changes)
        serializer = ChangeListSerializerV2(page or changes, many=True)
        if page is not None:
            return self.get_paginated_response(serializer.data)
        return Response(serializer.data)

    def change_detail(self, request, cve_id=None, change_id=None):
        cve = get_object_or_404(Cve, cve_id=cve_id)
        change = get_object_or_404(Change, id=change_id, cve=cve)
        return Response(ChangeDetailSerializerV2(change).data)


class WeaknessViewSet(V2ViewSetMixin, viewsets.ReadOnlyModelViewSet):
    serializer_class = WeaknessSerializerV2
    queryset = Weakness.objects.all().order_by("cwe_id")
    lookup_field = "cwe_id"
    scope_map = {
        # Global catalog: any valid organization token may read weaknesses.
        "list": None,
        "retrieve": None,
    }


class WeaknessCveViewSet(
    V2ViewSetMixin, viewsets.GenericViewSet, mixins.ListModelMixin
):
    serializer_class = CveListSerializerV2
    scope_map = {
        # Global catalog: any valid organization token may read CVEs by weakness.
        "list": None,
    }

    def get_queryset(self):
        weakness = get_object_or_404(Weakness, cwe_id=self.kwargs["weakness_cwe_id"])
        return (
            Cve.objects.order_by("-updated_at")
            .filter(weaknesses__contains=weakness.cwe_id)
            .all()
        )


class VendorViewSet(V2ViewSetMixin, viewsets.ReadOnlyModelViewSet):
    from cves.serializers import VendorListSerializer

    serializer_class = VendorListSerializer
    queryset = Vendor.objects.order_by("name").all()
    lookup_field = "name"
    lookup_url_kwarg = "name"
    scope_map = {
        # Global catalog: any valid organization token may read vendors.
        "list": None,
        "retrieve": None,
    }


class VendorCveViewSet(V2ViewSetMixin, viewsets.GenericViewSet, mixins.ListModelMixin):
    serializer_class = CveListSerializerV2
    scope_map = {
        # Global catalog: any valid organization token may read CVEs by vendor.
        "list": None,
    }

    def get_queryset(self):
        vendor = get_object_or_404(Vendor, name=self.kwargs["vendor_name"])
        return (
            Cve.objects.order_by("-updated_at")
            .filter(vendors__contains=vendor.name)
            .all()
        )


class ProductViewSet(V2ViewSetMixin, viewsets.ReadOnlyModelViewSet):
    from cves.serializers import ProductListSerializer

    serializer_class = ProductListSerializer
    lookup_field = "name"
    lookup_url_kwarg = "name"
    scope_map = {
        # Global catalog: any valid organization token may read products.
        "list": None,
        "retrieve": None,
    }

    def get_queryset(self):
        vendor = get_object_or_404(Vendor, name=self.kwargs["vendor_name"])
        return Product.objects.filter(vendor=vendor).order_by("name").all()


class ProductCveViewSet(V2ViewSetMixin, viewsets.GenericViewSet, mixins.ListModelMixin):
    from cves.constants import PRODUCT_SEPARATOR

    serializer_class = CveListSerializerV2
    scope_map = {
        # Global catalog: any valid organization token may read CVEs by product.
        "list": None,
    }

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


class ActivityViewSet(V2ViewSetMixin, viewsets.GenericViewSet, mixins.ListModelMixin):
    serializer_class = ChangeListSerializerV2
    scope_map = {
        # Global catalog: any valid organization token may read activity feed.
        "list": None,
    }

    def get_queryset(self):
        queryset = Change.objects.select_related("cve").order_by("-created_at")
        if self.request.query_params.get("view") == "subscriptions":
            org = getattr(self.request, "authenticated_organization", None)
            if org:
                vendors = org.get_projects_vendors()
                if vendors:
                    queryset = queryset.filter(cve__vendors__has_any_keys=vendors)
                else:
                    return Change.objects.none()
        return queryset


class StatisticsViewSet(V2ViewSetMixin, viewsets.ViewSet):
    scope_map = {
        # Global catalog: any valid organization token may read statistics.
        "list": None,
    }

    def list(self, request):
        from cves.models import Variable

        variables = Variable.objects.filter(name__startswith="statistics")
        data = {}
        for var in variables:
            data[var.name] = var.value
        return Response(data)
