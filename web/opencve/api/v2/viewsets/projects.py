import csv
import io
import secrets

from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from rest_framework import mixins, status, viewsets
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from changes.models import Report
from cves.models import Cve
from opencve.api.scopes import APIScope
from opencve.api.v2.mixins import V2APIViewMixin, V2ProjectScopedMixin, V2ViewSetMixin
from opencve.api.v2.serializers import (
    AutomationExecutionSerializerV2,
    AutomationRunResultSerializerV2,
    AutomationSerializerV2,
    CveCommentSerializerV2,
    CveTrackerUpdateSerializer,
    NotificationSerializerV2,
    ProjectCveSerializerV2,
    ProjectDetailSerializerV2,
    ProjectSerializerV2,
    ProjectWriteSerializerV2,
    ReportDetailSerializerV2,
    ReportSerializerV2,
    SubscriptionMutationSerializer,
)
from projects.models import (
    Automation,
    AutomationExecution,
    AutomationRunResult,
    CveComment,
    CveTracker,
    Notification,
    Project,
)
from projects.services.subscriptions import subscribe_project, unsubscribe_project
from projects.notifications import run_notification_try
from projects.utils import send_notification_confirmation_email
from users.models import User


class ProjectViewSet(V2ViewSetMixin, V2ProjectScopedMixin, viewsets.ModelViewSet):
    lookup_field = "name"
    lookup_url_kwarg = "name"
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]
    scope_map = {
        "list": APIScope.PROJECTS_READ,
        "retrieve": APIScope.PROJECTS_READ,
        "create": APIScope.PROJECTS_WRITE,
        "partial_update": APIScope.PROJECTS_WRITE,
        "update": APIScope.PROJECTS_WRITE,
        "destroy": APIScope.PROJECTS_WRITE,
    }

    def get_queryset(self):
        organization = self.get_organization()
        return Project.objects.filter(organization=organization).order_by("name")

    def get_serializer_class(self):
        if self.action in ("create", "partial_update", "update"):
            return ProjectWriteSerializerV2
        if self.action == "retrieve":
            return ProjectDetailSerializerV2
        return ProjectSerializerV2

    def perform_create(self, serializer):
        organization = self.get_organization()
        serializer.save(organization=organization)

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        serializer = self.get_serializer(page or queryset, many=True)
        data = serializer.data
        if page is not None:
            for item, project in zip(data, page):
                item["subscriptions_count"] = project.subscriptions_count
            return self.get_paginated_response(data)
        for item, project in zip(data, queryset):
            item["subscriptions_count"] = project.subscriptions_count
        return Response(data)


class ProjectSubscriptionViewSet(
    V2ViewSetMixin, V2ProjectScopedMixin, viewsets.GenericViewSet
):
    scope_map = {
        "list": APIScope.PROJECTS_READ,
        "create": APIScope.SUBSCRIPTIONS_WRITE,
        "destroy": APIScope.SUBSCRIPTIONS_WRITE,
    }

    def list(self, request, *args, **kwargs):
        project = self.get_project()
        return Response(ProjectDetailSerializerV2(project).data["subscriptions"])

    def create(self, request, *args, **kwargs):
        project = self.get_project()
        serializer = SubscriptionMutationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        subscribe_project(
            project,
            vendor_name=serializer.validated_data["vendor"],
            product_name=serializer.validated_data.get("product") or None,
        )
        project.refresh_from_db()
        return Response(
            ProjectDetailSerializerV2(project).data["subscriptions"],
            status=status.HTTP_201_CREATED,
        )

    def destroy(self, request, *args, **kwargs):
        project = self.get_project()
        vendor = request.query_params.get("vendor")
        product = request.query_params.get("product") or None
        if not vendor:
            raise ValidationError({"vendor": "This field is required."})
        unsubscribe_project(
            project,
            vendor_name=vendor,
            product_name=product,
        )
        project.refresh_from_db()
        return Response(ProjectDetailSerializerV2(project).data["subscriptions"])


class ProjectCveViewSet(
    V2ViewSetMixin, V2ProjectScopedMixin, viewsets.GenericViewSet, mixins.ListModelMixin
):
    scope_map = {
        "list": APIScope.PROJECTS_READ,
    }

    def get_queryset(self):
        project = self.get_project()
        vendors = project.subscriptions["vendors"] + project.subscriptions["products"]
        if not vendors:
            return Cve.objects.none()

        queryset = (
            Cve.objects.order_by("-updated_at")
            .filter(vendors__has_any_keys=vendors)
            .all()
        )

        status_filter = self.request.query_params.get("status")
        assignee = self.request.query_params.get("assignee")
        if status_filter:
            tracker_cves = CveTracker.objects.filter(project=project)
            if status_filter == "no_status":
                tracker_cves = tracker_cves.filter(
                    status__isnull=True
                ) | tracker_cves.filter(status="")
            else:
                tracker_cves = tracker_cves.filter(status=status_filter)
            queryset = queryset.filter(
                id__in=tracker_cves.values_list("cve_id", flat=True)
            )

        if assignee:
            tracker_cves = CveTracker.objects.filter(
                project=project, assignee__email=assignee
            )
            queryset = queryset.filter(
                id__in=tracker_cves.values_list("cve_id", flat=True)
            )

        q = self.request.query_params.get("q")
        if q:
            from cves.search import Search

            search = Search(q, request=self.request)
            if search.validate_parsing():
                queryset = queryset.filter(
                    id__in=search.query.values_list("id", flat=True)
                )

        return queryset

    def get_serializer_context(self):
        context = super().get_serializer_context()
        if self.action != "list":
            return context
        project = self.get_project()
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        items = page if page is not None else queryset
        cve_ids = [c.id for c in items]
        context["trackers"] = {
            t.cve_id: t
            for t in CveTracker.objects.filter(
                project=project, cve_id__in=cve_ids
            ).select_related("assignee")
        }
        return context

    def get_serializer_class(self):
        return ProjectCveSerializerV2

    def list(self, request, *args, **kwargs):
        if request.query_params.get("format") == "csv":
            return self._csv_export()
        return super().list(request, *args, **kwargs)

    def _csv_export(self):
        project = self.get_project()
        queryset = self.filter_queryset(self.get_queryset())
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(
            ["cve_id", "title", "description", "status", "assignee", "updated_at"]
        )
        trackers = {
            t.cve_id: t
            for t in CveTracker.objects.filter(
                project=project, cve_id__in=queryset.values_list("id", flat=True)[:5000]
            ).select_related("assignee")
        }
        for cve in queryset[:5000]:
            tracker = trackers.get(cve.id)
            writer.writerow(
                [
                    cve.cve_id,
                    cve.title or "",
                    cve.description or "",
                    tracker.status if tracker else "",
                    tracker.assignee.email if tracker and tracker.assignee_id else "",
                    cve.updated_at,
                ]
            )
        response = HttpResponse(buffer.getvalue(), content_type="text/csv")
        response["Content-Disposition"] = (
            f'attachment; filename="{project.name}-cves.csv"'
        )
        return response


class ProjectCveDetailViewSet(V2ViewSetMixin, V2ProjectScopedMixin, viewsets.ViewSet):
    scope_map = {
        "retrieve": APIScope.PROJECTS_READ,
        "partial_update": APIScope.TRACKER_WRITE,
    }

    def retrieve(self, request, organization_name=None, project_name=None, cve_id=None):
        project = self.get_project()
        cve = get_object_or_404(Cve, cve_id=cve_id)
        tracker = (
            CveTracker.objects.filter(project=project, cve=cve)
            .select_related("assignee")
            .first()
        )
        context = {"trackers": {cve.id: tracker} if tracker else {}}
        return Response(ProjectCveSerializerV2(cve, context=context).data)

    def partial_update(
        self, request, organization_name=None, project_name=None, cve_id=None
    ):
        project = self.get_project()
        cve = get_object_or_404(Cve, cve_id=cve_id)
        serializer = CveTrackerUpdateSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)

        assignee = serializer.validated_data.get("assignee", Ellipsis)
        status_value = serializer.validated_data.get("status", Ellipsis)
        assignee_user = Ellipsis
        if assignee is not Ellipsis:
            assignee_user = None
            if assignee:
                assignee_user = get_object_or_404(
                    User,
                    email=assignee,
                    membership__organization=project.organization,
                    membership__date_joined__isnull=False,
                )

        tracker = CveTracker.update_tracker(
            project=project,
            cve=cve,
            assignee=assignee_user,
            status=status_value,
        )
        context = {"trackers": {cve.id: tracker} if tracker else {}}
        return Response(ProjectCveSerializerV2(cve, context=context).data)


class ProjectCveCommentViewSet(
    V2ViewSetMixin, V2ProjectScopedMixin, viewsets.ModelViewSet
):
    serializer_class = CveCommentSerializerV2
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]
    scope_map = {
        "list": APIScope.PROJECTS_READ,
        "create": APIScope.COMMENTS_WRITE,
        "partial_update": APIScope.COMMENTS_WRITE,
        "update": APIScope.COMMENTS_WRITE,
        "destroy": APIScope.COMMENTS_WRITE,
    }

    def get_queryset(self):
        project = self.get_project()
        cve = get_object_or_404(Cve, cve_id=self.kwargs["cve_id"])
        return CveComment.objects.filter(
            project=project, cve=cve, parent__isnull=True
        ).select_related("author")

    def perform_create(self, serializer):
        project = self.get_project()
        cve = get_object_or_404(Cve, cve_id=self.kwargs["cve_id"])
        serializer.save(project=project, cve=cve, author=self.request.api_actor)

    def perform_update(self, serializer):
        if serializer.instance.author_id != getattr(self.request.api_actor, "id", None):
            raise PermissionDenied()
        serializer.save(edited=True)

    def perform_destroy(self, instance):
        if instance.author_id != getattr(self.request.api_actor, "id", None):
            raise PermissionDenied()
        instance.delete()


class NotificationViewSet(V2ViewSetMixin, V2ProjectScopedMixin, viewsets.ModelViewSet):
    serializer_class = NotificationSerializerV2
    lookup_field = "name"
    lookup_url_kwarg = "notification_name"
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]
    scope_map = {
        "list": APIScope.PROJECTS_READ,
        "retrieve": APIScope.PROJECTS_READ,
        "create": APIScope.NOTIFICATIONS_WRITE,
        "partial_update": APIScope.NOTIFICATIONS_WRITE,
        "update": APIScope.NOTIFICATIONS_WRITE,
        "destroy": APIScope.NOTIFICATIONS_WRITE,
    }

    def get_queryset(self):
        project = self.get_project()
        return Notification.objects.filter(project=project).order_by("name")

    def perform_create(self, serializer):
        project = self.get_project()
        notification_type = self.request.data.get("type")
        if notification_type not in ("email", "webhook", "slack"):
            raise ValidationError({"type": "Must be email, webhook, or slack."})

        extras = self.request.data.get("configuration", {}).get("extras", {})
        is_enabled = True
        if notification_type == "email":
            is_enabled = False
            extras["created_by_email"] = self.request.api_actor.email
            extras["confirmation_token"] = secrets.token_urlsafe(32)

        notification = serializer.save(
            project=project,
            type=notification_type,
            configuration={"extras": extras},
            is_enabled=is_enabled,
        )
        if notification_type == "email":
            send_notification_confirmation_email(notification, self.request)


class NotificationTestView(V2APIViewMixin, APIView):
    scope_map = {
        "post": APIScope.NOTIFICATIONS_WRITE,
    }

    def post(
        self, request, organization_name=None, project_name=None, notification_name=None
    ):
        organization = request.authenticated_organization
        if organization.name != organization_name:
            from rest_framework.exceptions import NotFound

            raise NotFound()
        project = get_object_or_404(
            Project, organization=organization, name=project_name
        )
        notification = get_object_or_404(
            Notification, project=project, name=notification_name
        )
        extras = notification.configuration.get("extras", {})
        try_result = run_notification_try(
            notification.type,
            extras,
            project_name=notification.project.name,
            organization_name=notification.project.organization.name,
            notification_name=notification.name,
            project_subscriptions=(
                notification.project.subscriptions.get("vendors", [])
                + notification.project.subscriptions.get("products", [])
            ),
            triggered_by_email=getattr(request.api_actor, "email", "") or "",
        )
        result = try_result.as_template_dict()
        if result.get("success"):
            return Response({"status": "sent", "details": result})
        return Response(
            {"status": "failed", "details": result},
            status=status.HTTP_400_BAD_REQUEST,
        )


class AutomationViewSet(V2ViewSetMixin, V2ProjectScopedMixin, viewsets.ModelViewSet):
    serializer_class = AutomationSerializerV2
    lookup_field = "name"
    lookup_url_kwarg = "automation_name"
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]
    scope_map = {
        "list": APIScope.PROJECTS_READ,
        "retrieve": APIScope.PROJECTS_READ,
        "create": APIScope.AUTOMATIONS_WRITE,
        "partial_update": APIScope.AUTOMATIONS_WRITE,
        "update": APIScope.AUTOMATIONS_WRITE,
        "destroy": APIScope.AUTOMATIONS_WRITE,
    }

    def get_queryset(self):
        project = self.get_project()
        return Automation.objects.filter(project=project).order_by("name")

    def perform_create(self, serializer):
        project = self.get_project()
        serializer.save(project=project)


class AutomationExecutionViewSet(
    V2ViewSetMixin, V2ProjectScopedMixin, viewsets.ReadOnlyModelViewSet
):
    serializer_class = AutomationExecutionSerializerV2
    lookup_field = "id"
    lookup_url_kwarg = "execution_id"
    scope_map = {
        "list": APIScope.PROJECTS_READ,
        "retrieve": APIScope.PROJECTS_READ,
    }

    def get_queryset(self):
        project = self.get_project()
        automation = get_object_or_404(
            Automation,
            project=project,
            name=self.kwargs["automation_name"],
        )
        return AutomationExecution.objects.filter(automation=automation).order_by(
            "-executed_at"
        )

    def retrieve(self, request, *args, **kwargs):
        execution = self.get_object()
        data = AutomationExecutionSerializerV2(execution).data
        data["results"] = AutomationRunResultSerializerV2(
            AutomationRunResult.objects.filter(automation_execution=execution),
            many=True,
        ).data
        return Response(data)


class ReportViewSet(
    V2ViewSetMixin, V2ProjectScopedMixin, viewsets.ReadOnlyModelViewSet
):
    serializer_class = ReportSerializerV2
    lookup_field = "id"
    lookup_url_kwarg = "report_id"
    scope_map = {
        "list": APIScope.REPORTS_READ,
        "retrieve": APIScope.REPORTS_READ,
    }

    def get_queryset(self):
        project = self.get_project()
        queryset = Report.objects.filter(project=project).order_by("-day")
        period = self.request.query_params.get("period_type")
        if period in ("daily", "weekly"):
            queryset = queryset.filter(period_type=period)
        return queryset

    def get_serializer_class(self):
        if self.action == "retrieve":
            return ReportDetailSerializerV2
        return ReportSerializerV2
