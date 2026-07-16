from django.db.models import F
from django.shortcuts import get_object_or_404
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import mixins, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response

from changes.models import Change
from cves.models import Cve, Product, Vendor, Weakness
from cves.search import BadQueryException, MaxFieldsExceededException, Search
from opencve.api.v2.mixins import ViewSetMixin
from opencve.api.v2.scopes import APIScope
from opencve.api.v2.pagination import pagination_openapi_parameters
from opencve.api.v2.openapi import (
    CVES_TAG,
    CVE_LIST_QUERY_PARAMS,
    CVE_RETRIEVE_INCLUDE_FIELDS,
    CVE_RETRIEVE_QUERY_PARAMS,
    CVE_RETRIEVE_RESPONSE_EXAMPLE,
    CVE_CHANGE_DETAIL_RESPONSE_EXAMPLE,
    CVE_CHANGE_LIST_RESPONSE_EXAMPLE,
    VENDORS_TAG,
    VENDOR_NAME,
    PRODUCT_NAME,
    WEAKNESSES_TAG,
)
from opencve.api.v2.serializers import (
    ChangeDetailSerializer,
    ChangeListSerializer,
    CveDetailSerializer,
    CveListSerializer,
    ProductListSerializer,
    VendorListSerializer,
    WeaknessSerializer,
)


@extend_schema(tags=[CVES_TAG])
@extend_schema_view(
    list=extend_schema(
        summary="List all CVEs.",
        parameters=CVE_LIST_QUERY_PARAMS,
        description=("Optionally filter results with the `q` advanced search query."),
    ),
    retrieve=extend_schema(
        summary="Retrieve a CVE.",
        parameters=CVE_RETRIEVE_QUERY_PARAMS,
        responses={200: CveDetailSerializer},
        examples=[CVE_RETRIEVE_RESPONSE_EXAMPLE],
    ),
)
class CveViewSet(ViewSetMixin, viewsets.ReadOnlyModelViewSet):
    lookup_field = "cve_id"
    queryset = Cve.objects.order_by("-updated_at").all()
    scope_map = {
        "list": APIScope.CATALOG_READ,
        "retrieve": APIScope.CATALOG_READ,
        "changes": APIScope.CATALOG_READ,
        "change_detail": APIScope.CATALOG_READ,
    }

    def get_serializer_class(self):
        if self.action == "retrieve":
            return CveDetailSerializer
        return CveListSerializer

    def get_queryset(self):
        if self.action == "retrieve":
            return self.queryset

        q = self.request.query_params.get("q")
        if not q:
            return self.queryset

        # Validate the search query
        search = Search(q, request=self.request)
        if not search.validate_parsing():
            raise ValidationError({"q": str(search.error)})

        try:
            return search.query
        except (BadQueryException, MaxFieldsExceededException) as exc:
            raise ValidationError({"q": str(exc)}) from exc

    def _parse_include_params(self, request):
        include_param = request.query_params.get("include", "")
        if not include_param:
            return set()

        # Parse the include parameters
        includes = {item.strip() for item in include_param.split(",") if item.strip()}
        invalid = includes - CVE_RETRIEVE_INCLUDE_FIELDS

        if invalid:
            allowed = ", ".join(sorted(CVE_RETRIEVE_INCLUDE_FIELDS))
            raise ValidationError(
                {
                    "include": (
                        f"Unknown include value(s): {', '.join(sorted(invalid))}. "
                        f"Allowed values: {allowed}."
                    )
                }
            )

        return includes

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        data = serializer.data
        includes = self._parse_include_params(request)

        if "nvd_cpe_configurations" in includes:
            data["nvd_cpe_configurations"] = instance.nvd_json.get("configurations", [])

        if "references" in includes:
            data["references"] = instance.nvd_json.get("references", [])

        return Response(data)

    @extend_schema(
        operation_id="cves_changes_list",
        summary="List changes for a CVE.",
        parameters=pagination_openapi_parameters(),
        examples=[CVE_CHANGE_LIST_RESPONSE_EXAMPLE],
    )
    @action(detail=True, methods=["get"], url_path="changes")
    def changes(self, request, cve_id=None):
        cve = self.get_object()
        changes = Change.objects.filter(cve=cve).order_by("-created_at")

        # Paginate and serialize the changes
        page = self.paginate_queryset(changes)
        serializer = ChangeListSerializer(
            page if page is not None else changes, many=True
        )

        if page is not None:
            return self.get_paginated_response(serializer.data)

        return Response(serializer.data)

    @extend_schema(
        operation_id="cves_change_detail_retrieve",
        summary="Retrieve a CVE change.",
        responses={200: ChangeDetailSerializer},
        examples=[CVE_CHANGE_DETAIL_RESPONSE_EXAMPLE],
    )
    def change_detail(self, request, cve_id=None, change_id=None):
        cve = get_object_or_404(Cve, cve_id=cve_id)
        change = get_object_or_404(Change, id=change_id, cve=cve)
        return Response(ChangeDetailSerializer(change).data)


@extend_schema(tags=[WEAKNESSES_TAG])
@extend_schema_view(
    list=extend_schema(summary="List CWE weaknesses."),
    retrieve=extend_schema(summary="Retrieve a CWE weakness."),
)
class WeaknessViewSet(ViewSetMixin, viewsets.ReadOnlyModelViewSet):
    serializer_class = WeaknessSerializer
    queryset = Weakness.objects.all().order_by(F("name").desc(nulls_last=True))
    lookup_field = "cwe_id"
    scope_map = {
        "list": APIScope.CATALOG_READ,
        "retrieve": APIScope.CATALOG_READ,
    }


@extend_schema(tags=[WEAKNESSES_TAG])
@extend_schema_view(
    list=extend_schema(summary="List CVEs associated with a weakness."),
)
class WeaknessCveViewSet(ViewSetMixin, viewsets.GenericViewSet, mixins.ListModelMixin):
    serializer_class = CveListSerializer
    scope_map = {
        "list": APIScope.CATALOG_READ,
    }

    def get_queryset(self):
        weakness = get_object_or_404(Weakness, cwe_id=self.kwargs["cwe_id"])
        return (
            Cve.objects.order_by("-updated_at")
            .filter(weaknesses__contains=weakness.cwe_id)
            .all()
        )


@extend_schema(tags=[VENDORS_TAG])
@extend_schema_view(
    list=extend_schema(summary="List all vendors."),
    retrieve=extend_schema(summary="Retrieve a vendor."),
)
class VendorViewSet(ViewSetMixin, viewsets.ReadOnlyModelViewSet):
    serializer_class = VendorListSerializer
    queryset = Vendor.objects.order_by("name").all()
    lookup_field = "name"
    lookup_url_kwarg = "name"
    scope_map = {
        "list": APIScope.CATALOG_READ,
        "retrieve": APIScope.CATALOG_READ,
    }


@extend_schema(tags=[VENDORS_TAG])
@extend_schema_view(
    list=extend_schema(summary="List CVEs associated with a vendor."),
)
class VendorCveViewSet(ViewSetMixin, viewsets.GenericViewSet, mixins.ListModelMixin):
    serializer_class = CveListSerializer
    scope_map = {
        "list": APIScope.CATALOG_READ,
    }

    def get_queryset(self):
        vendor = get_object_or_404(Vendor, name=self.kwargs["vendor_name"])
        return (
            Cve.objects.order_by("-updated_at")
            .filter(vendors__contains=vendor.name)
            .all()
        )


@extend_schema(tags=[VENDORS_TAG])
@extend_schema_view(
    list=extend_schema(
        summary="List products for a vendor.",
        parameters=[VENDOR_NAME],
    ),
    retrieve=extend_schema(
        summary="Retrieve a product.",
        parameters=[VENDOR_NAME, PRODUCT_NAME],
    ),
)
class ProductViewSet(ViewSetMixin, viewsets.ReadOnlyModelViewSet):
    serializer_class = ProductListSerializer
    lookup_field = "name"
    lookup_url_kwarg = "name"
    scope_map = {
        "list": APIScope.CATALOG_READ,
        "retrieve": APIScope.CATALOG_READ,
    }

    def get_queryset(self):
        vendor = get_object_or_404(Vendor, name=self.kwargs["vendor_name"])
        return Product.objects.filter(vendor=vendor).order_by("name").all()


@extend_schema(tags=[VENDORS_TAG])
@extend_schema_view(
    list=extend_schema(summary="List CVEs associated with a product."),
)
class ProductCveViewSet(ViewSetMixin, viewsets.GenericViewSet, mixins.ListModelMixin):
    serializer_class = CveListSerializer
    scope_map = {
        "list": APIScope.CATALOG_READ,
    }

    def get_queryset(self):
        vendor = get_object_or_404(Vendor, name=self.kwargs["vendor_name"])
        product = get_object_or_404(
            Product, vendor=vendor, name=self.kwargs["product_name"]
        )
        return (
            Cve.objects.order_by("-updated_at")
            .filter(vendors__contains=product.vendored_name)
            .all()
        )
