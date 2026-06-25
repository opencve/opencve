from django.shortcuts import get_object_or_404
from rest_framework import mixins, status, viewsets
from rest_framework.response import Response

from opencve.api.scopes import APIScope
from opencve.api.v2.mixins import V2OrganizationScopedMixin, V2ViewSetMixin
from opencve.api.v2.serializers import (
    MembershipCreateSerializer,
    MembershipSerializerV2,
    MembershipUpdateSerializer,
    OrganizationSerializerV2,
    OrganizationWriteSerializerV2,
)
from organizations.auditlog import (
    apply_audit_log_get_filters,
    build_audit_log_queryset,
    extend_audit_log_pks_with_deleted,
    get_audit_log_display_data,
    get_organization_audit_log_pks,
)
from organizations.models import Membership, Organization
from organizations.services.memberships import (
    invite_member,
    remove_member,
    update_member_role,
)


class OrganizationViewSet(
    V2ViewSetMixin,
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    lookup_field = "name"
    lookup_url_kwarg = "name"
    http_method_names = ["get", "patch", "head", "options"]
    scope_map = {
        "list": APIScope.ORG_READ,
        "retrieve": APIScope.ORG_READ,
        "partial_update": APIScope.ORG_WRITE,
        "update": APIScope.ORG_WRITE,
    }

    def get_queryset(self):
        return (
            Organization.objects.filter(id=self.request.authenticated_organization.id)
            .order_by("name")
            .all()
        )

    def get_serializer_class(self):
        if self.action in ("partial_update", "update"):
            return OrganizationWriteSerializerV2
        return OrganizationSerializerV2


class OrganizationMemberViewSet(
    V2ViewSetMixin,
    V2OrganizationScopedMixin,
    mixins.ListModelMixin,
    mixins.CreateModelMixin,
    mixins.UpdateModelMixin,
    mixins.DestroyModelMixin,
    viewsets.GenericViewSet,
):
    serializer_class = MembershipSerializerV2
    lookup_field = "id"
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]
    scope_map = {
        "list": APIScope.MEMBERS_READ,
        "create": APIScope.MEMBERS_WRITE,
        "partial_update": APIScope.MEMBERS_WRITE,
        "update": APIScope.MEMBERS_WRITE,
        "destroy": APIScope.MEMBERS_WRITE,
    }

    def get_queryset(self):
        organization = self.get_organization()
        return organization.membership_set.order_by("date_invited")

    def create(self, request, *args, **kwargs):
        organization = self.get_organization()
        serializer = MembershipCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        membership = invite_member(
            organization=organization,
            email=serializer.validated_data["email"],
            role=serializer.validated_data["role"],
        )
        return Response(
            MembershipSerializerV2(membership).data,
            status=status.HTTP_201_CREATED,
        )

    def partial_update(self, request, *args, **kwargs):
        membership = self.get_object()
        serializer = MembershipUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        membership = update_member_role(
            membership=membership,
            role=serializer.validated_data["role"],
        )
        return Response(MembershipSerializerV2(membership).data)

    def perform_destroy(self, instance):
        remove_member(membership=instance)


class OrganizationAuditLogViewSet(
    V2ViewSetMixin,
    V2OrganizationScopedMixin,
    mixins.ListModelMixin,
    viewsets.GenericViewSet,
):
    scope_map = {
        "list": APIScope.ORG_READ,
    }

    def list(self, request, *args, **kwargs):
        organization = self.get_organization()
        pks_dict = get_organization_audit_log_pks(organization)
        pks_dict = extend_audit_log_pks_with_deleted(organization, pks_dict)
        entries_qs = build_audit_log_queryset(pks_dict)
        entries_qs, _ = apply_audit_log_get_filters(entries_qs, request.query_params)
        page = self.paginate_queryset(entries_qs)
        entries = page or entries_qs
        display = get_audit_log_display_data(entries)
        data = []
        for entry in entries:
            info = display.get(entry.id, {})
            data.append(
                {
                    "id": entry.id,
                    "timestamp": entry.timestamp,
                    "action": entry.action,
                    "actor": entry.actor.username if entry.actor_id else None,
                    "resource": info.get("resource_label"),
                    "object_repr": info.get("display_object_repr"),
                    "changes": info.get("display_changes_dict"),
                }
            )
        if page is not None:
            return self.get_paginated_response(data)
        return Response(data)
