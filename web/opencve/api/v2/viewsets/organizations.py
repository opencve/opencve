from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import mixins, status, viewsets
from rest_framework.response import Response

from opencve.api.v2.scopes import APIScope
from opencve.api.v2.openapi import (
    MEMBERSHIP_CREATE_REQUEST_EXAMPLE,
    MEMBERSHIP_CREATE_RESPONSE_EXAMPLE,
    MEMBERSHIP_UPDATE_REQUEST_EXAMPLE,
    MEMBERSHIP_UPDATE_RESPONSE_EXAMPLE,
    ORGANIZATIONS_TAG,
    ORGANIZATION_UPDATE_REQUEST_EXAMPLE,
    ORGANIZATION_UPDATE_RESPONSE_EXAMPLE,
    ORG_PATH_PARAMS,
)
from opencve.api.v2.mixins import OrganizationScopedMixin, ViewSetMixin
from opencve.api.v2.serializers import (
    AuditLogEntrySerializer,
    MembershipCreateSerializer,
    MembershipSerializer,
    MembershipUpdateSerializer,
    OrganizationSerializer,
    OrganizationWriteSerializer,
)
from auditlog.models import LogEntry
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


@extend_schema(tags=[ORGANIZATIONS_TAG])
@extend_schema_view(
    list=extend_schema(
        summary="List organizations accessible with the current token.",
    ),
    retrieve=extend_schema(
        summary="Retrieve the current organization.",
    ),
    partial_update=extend_schema(
        summary="Update the current organization.",
        request=OrganizationWriteSerializer,
        responses={200: OrganizationWriteSerializer},
        examples=[
            ORGANIZATION_UPDATE_REQUEST_EXAMPLE,
            ORGANIZATION_UPDATE_RESPONSE_EXAMPLE,
        ],
    ),
)
class OrganizationViewSet(
    ViewSetMixin,
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
    }
    queryset = Organization.objects.none()

    def get_queryset(self):
        if self.is_schema_generation:
            return Organization.objects.none()
        return (
            Organization.objects.filter(id=self.request.authenticated_organization.id)
            .order_by("name")
            .all()
        )

    def get_serializer_class(self):
        if self.action in ("partial_update", "update"):
            return OrganizationWriteSerializer
        return OrganizationSerializer


@extend_schema(parameters=ORG_PATH_PARAMS, tags=[ORGANIZATIONS_TAG])
@extend_schema_view(
    list=extend_schema(summary="List members of an organization."),
    create=extend_schema(
        summary="Invite a member to an organization.",
        request=MembershipCreateSerializer,
        responses={201: MembershipSerializer},
        examples=[
            MEMBERSHIP_CREATE_REQUEST_EXAMPLE,
            MEMBERSHIP_CREATE_RESPONSE_EXAMPLE,
        ],
    ),
    partial_update=extend_schema(
        summary="Update a member role.",
        request=MembershipUpdateSerializer,
        responses={200: MembershipSerializer},
        examples=[
            MEMBERSHIP_UPDATE_REQUEST_EXAMPLE,
            MEMBERSHIP_UPDATE_RESPONSE_EXAMPLE,
        ],
    ),
    destroy=extend_schema(summary="Remove a member from an organization."),
)
class OrganizationMemberViewSet(
    ViewSetMixin,
    OrganizationScopedMixin,
    mixins.ListModelMixin,
    mixins.CreateModelMixin,
    mixins.UpdateModelMixin,
    mixins.DestroyModelMixin,
    viewsets.GenericViewSet,
):
    serializer_class = MembershipSerializer
    lookup_field = "id"
    queryset = Membership.objects.none()
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]
    scope_map = {
        "list": APIScope.MEMBERS_READ,
        "create": APIScope.MEMBERS_WRITE,
        "partial_update": APIScope.MEMBERS_WRITE,
        "destroy": APIScope.MEMBERS_WRITE,
    }

    def get_queryset(self):
        if self.is_schema_generation:
            return Membership.objects.none()
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
            request=request,
        )
        return Response(
            MembershipSerializer(membership).data,
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
        return Response(MembershipSerializer(membership).data)

    def perform_destroy(self, instance):
        remove_member(membership=instance)


@extend_schema(parameters=ORG_PATH_PARAMS, tags=[ORGANIZATIONS_TAG])
@extend_schema_view(
    list=extend_schema(summary="List audit log entries for an organization."),
)
class OrganizationAuditLogViewSet(
    ViewSetMixin,
    OrganizationScopedMixin,
    mixins.ListModelMixin,
    viewsets.GenericViewSet,
):
    serializer_class = AuditLogEntrySerializer
    queryset = LogEntry.objects.none()
    scope_map = {
        "list": APIScope.AUDIT_LOGS_READ,
    }

    def get_queryset(self):
        return LogEntry.objects.none()

    def list(self, request, *args, **kwargs):
        organization = self.get_organization()

        # Collect audit log entry PKs for all org-related objects.
        pks_dict = get_organization_audit_log_pks(organization)
        pks_dict = extend_audit_log_pks_with_deleted(organization, pks_dict)

        entries_qs = build_audit_log_queryset(pks_dict)
        entries_qs, _ = apply_audit_log_get_filters(entries_qs, request.query_params)

        page = self.paginate_queryset(entries_qs)
        entries = page if page is not None else entries_qs

        # Enrich raw LogEntry rows with human-readable labels and change diffs.
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
