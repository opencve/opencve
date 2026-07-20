import secrets

from django.db.models import Exists, OuterRef, Prefetch, Q
from django.shortcuts import get_object_or_404
from drf_spectacular.helpers import forced_singular_serializer
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import mixins, status, viewsets
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.response import Response

from changes.models import Change, Report
from cves.models import Cve
from cves.search import (
    BadQueryException,
    MaxFieldsExceededException,
    Search,
)
from opencve.api.v2.scopes import APIScope
from opencve.api.v2.mixins import ProjectScopedMixin, ViewSetMixin
from opencve.api.v2.openapi import (
    AUTOMATION_CREATE_REQUEST_EXAMPLE,
    AUTOMATION_CREATE_RESPONSE_EXAMPLE,
    AUTOMATION_DETAIL_RESPONSE_EXAMPLE,
    AUTOMATION_EXECUTION_DETAIL_RESPONSE_EXAMPLE,
    AUTOMATION_UPDATE_REQUEST_EXAMPLE,
    AUTOMATION_UPDATE_RESPONSE_EXAMPLE,
    AUTOMATIONS_TAG,
    NOTIFICATION_CREATE_REQUEST_EXAMPLE,
    NOTIFICATION_RESPONSE_EXAMPLE,
    NOTIFICATION_UPDATE_REQUEST_EXAMPLE,
    NOTIFICATIONS_TAG,
    ORG_PATH_PARAMS,
    ORG_PROJECT_AUTOMATION_PATH_PARAMS,
    ORG_PROJECT_CVE_PATH_PARAMS,
    ORG_PROJECT_PATH_PARAMS,
    ORG_PROJECT_REPORT_PATH_PARAMS,
    PROJECT_CREATE_EXAMPLE,
    PROJECT_CREATE_RESPONSE_EXAMPLE,
    PROJECT_CVE_DETAIL_RESPONSE_EXAMPLE,
    PROJECT_CVE_TRACKER_UPDATE_REQUEST_EXAMPLE,
    PROJECT_DETAIL_RESPONSE_EXAMPLE,
    PROJECT_UPDATE_EXAMPLE,
    PROJECTS_TAG,
    REPORT_DETAIL_RESPONSE_EXAMPLE,
    REPORT_LIST_ITEM_EXAMPLE,
    REPORTS_TAG,
    SUBSCRIPTION_CREATE_REQUEST_EXAMPLE,
    SUBSCRIPTION_DELETE_QUERY_PARAMS,
    SUBSCRIPTION_LIST_RESPONSE_EXAMPLE,
    SUBSCRIPTION_REPLACE_REQUEST_EXAMPLE,
    SUBSCRIPTIONS_TAG,
    TRACKER_TAG,
)
from opencve.api.v2.serializers import (
    AutomationExecutionDetailSerializer,
    AutomationExecutionSerializer,
    AutomationListSerializer,
    AutomationRunResultSerializer,
    AutomationSerializer,
    AutomationWriteSerializer,
    CveListSerializer,
    CveTrackerUpdateSerializer,
    NotificationSerializer,
    NotificationWriteSerializer,
    ProjectCveSerializer,
    ProjectDetailSerializer,
    ProjectSerializer,
    ProjectWriteSerializer,
    ReportDetailSerializer,
    ReportSerializer,
    SubscriptionListSerializer,
    SubscriptionMutationSerializer,
)
from projects.models import (
    Automation,
    AutomationExecution,
    AutomationRunResult,
    CveTracker,
    Notification,
    Project,
)
from projects.services.notifications import (
    build_notification_extras,
    normalize_configuration_input,
)
from projects.services.subscriptions import (
    replace_project_subscriptions,
    subscribe_project,
    subscriptions_to_api_format_from_project,
    unsubscribe_project,
)
from projects.utils import send_notification_confirmation_email
from users.models import User


def _project_subscription_vendor_keys(project):
    """Return the vendor keys from the project subscriptions"""
    return project.subscriptions["vendors"] + project.subscriptions["products"]


def _cve_matches_project_subscriptions(project, cve):
    """Return True if the CVE matches the project subscriptions"""
    vendors = _project_subscription_vendor_keys(project)
    if not vendors:
        return False
    return Cve.objects.filter(id=cve.id, vendors__has_any_keys=vendors).exists()


@extend_schema(tags=[PROJECTS_TAG])
@extend_schema(parameters=ORG_PATH_PARAMS)
@extend_schema_view(
    list=extend_schema(summary="List projects in an organization."),
    create=extend_schema(
        summary="Create a project in an organization.",
        request=ProjectWriteSerializer,
        responses={201: ProjectDetailSerializer},
        examples=[
            PROJECT_CREATE_EXAMPLE,
            PROJECT_CREATE_RESPONSE_EXAMPLE,
        ],
    ),
    partial_update=extend_schema(
        summary="Update a project.",
        request=ProjectWriteSerializer,
        responses={200: ProjectDetailSerializer},
        examples=[
            PROJECT_UPDATE_EXAMPLE,
            PROJECT_DETAIL_RESPONSE_EXAMPLE,
        ],
    ),
    retrieve=extend_schema(
        summary="Retrieve a project.",
        responses={200: ProjectDetailSerializer},
        examples=[PROJECT_DETAIL_RESPONSE_EXAMPLE],
    ),
    destroy=extend_schema(summary="Delete a project."),
)
class ProjectViewSet(ViewSetMixin, ProjectScopedMixin, viewsets.ModelViewSet):
    lookup_field = "name"
    lookup_url_kwarg = "name"
    queryset = Project.objects.none()
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]
    scope_map = {
        "list": APIScope.PROJECTS_READ,
        "retrieve": APIScope.PROJECTS_READ,
        "create": APIScope.PROJECTS_WRITE,
        "partial_update": APIScope.PROJECTS_WRITE,
        "destroy": APIScope.PROJECTS_WRITE,
    }

    def get_queryset(self):
        if self.is_schema_generation:
            return Project.objects.none()

        organization = self.get_organization()
        return Project.objects.filter(organization=organization).order_by("name")

    def get_serializer_class(self):
        if self.action in ("create", "partial_update", "update"):
            return ProjectWriteSerializer

        if self.action == "retrieve":
            return ProjectDetailSerializer

        return ProjectSerializer

    def get_serializer_context(self):
        context = super().get_serializer_context()

        if self.action in ("create", "partial_update", "update"):
            context["organization"] = self.get_organization()

        return context

    def perform_create(self, serializer):
        organization = self.get_organization()
        serializer.save(organization=organization)

    def create(self, request, *args, **kwargs):
        serializer = ProjectWriteSerializer(
            data=request.data,
            context=self.get_serializer_context(),
        )

        # Validate and save the project
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        return Response(
            ProjectDetailSerializer(serializer.instance).data,
            status=status.HTTP_201_CREATED,
        )

    def partial_update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = ProjectWriteSerializer(
            instance,
            data=request.data,
            partial=True,
            context=self.get_serializer_context(),
        )

        # Validate and save the project
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(ProjectDetailSerializer(instance).data)

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        serializer = self.get_serializer(
            page if page is not None else queryset, many=True
        )
        data = serializer.data

        # Paginate the projects
        if page is not None:
            for item, project in zip(data, page):
                item["subscriptions_count"] = project.subscriptions_count
            return self.get_paginated_response(data)

        for item, project in zip(data, queryset):
            item["subscriptions_count"] = project.subscriptions_count

        return Response(data)


@extend_schema(tags=[SUBSCRIPTIONS_TAG])
@extend_schema(parameters=ORG_PROJECT_PATH_PARAMS)
@extend_schema_view(
    create=extend_schema(
        summary="Add a subscription to a project.",
        request=SubscriptionMutationSerializer,
        responses={200: SubscriptionListSerializer},
        examples=[
            SUBSCRIPTION_CREATE_REQUEST_EXAMPLE,
            SUBSCRIPTION_LIST_RESPONSE_EXAMPLE,
        ],
    ),
    update=extend_schema(
        summary="Replace all subscriptions for a project.",
        request=SubscriptionListSerializer,
        responses={200: SubscriptionListSerializer},
        examples=[
            SUBSCRIPTION_REPLACE_REQUEST_EXAMPLE,
            SUBSCRIPTION_LIST_RESPONSE_EXAMPLE,
        ],
    ),
    destroy=extend_schema(
        summary="Remove a subscription from a project.",
        parameters=ORG_PROJECT_PATH_PARAMS + SUBSCRIPTION_DELETE_QUERY_PARAMS,
        responses={200: SubscriptionListSerializer},
        examples=[SUBSCRIPTION_LIST_RESPONSE_EXAMPLE],
    ),
)
class ProjectSubscriptionViewSet(
    ViewSetMixin, ProjectScopedMixin, viewsets.GenericViewSet
):
    queryset = Project.objects.none()
    pagination_class = None
    scope_map = {
        "list": APIScope.SUBSCRIPTIONS_READ,
        "create": APIScope.SUBSCRIPTIONS_WRITE,
        "update": APIScope.SUBSCRIPTIONS_WRITE,
        "destroy": APIScope.SUBSCRIPTIONS_WRITE,
    }

    def get_serializer_class(self):
        if self.action == "create":
            return SubscriptionMutationSerializer
        return SubscriptionListSerializer

    @staticmethod
    def _subscriptions_response(project):
        return Response(subscriptions_to_api_format_from_project(project))

    @extend_schema(
        summary="Retrieve subscriptions for a project.",
        responses={200: forced_singular_serializer(SubscriptionListSerializer)},
        examples=[SUBSCRIPTION_LIST_RESPONSE_EXAMPLE],
    )
    def list(self, request, *args, **kwargs):
        return self._subscriptions_response(self.get_project())

    def create(self, request, *args, **kwargs):
        project = self.get_project()
        serializer = SubscriptionMutationSerializer(data=request.data)

        # Validate and subscribe the project
        serializer.is_valid(raise_exception=True)
        subscribe_project(
            project,
            vendor_name=serializer.validated_data["vendor"],
            product_name=serializer.validated_data.get("product") or None,
        )

        project.refresh_from_db()
        return self._subscriptions_response(project)

    def update(self, request, *args, **kwargs):
        project = self.get_project()
        serializer = SubscriptionListSerializer(data=request.data)

        # Validate and replace the project subscriptions
        serializer.is_valid(raise_exception=True)
        replace_project_subscriptions(
            project,
            vendors=serializer.validated_data["vendors"],
            products_by_vendor=serializer.validated_data["products"],
        )

        project.refresh_from_db()
        return self._subscriptions_response(project)

    def destroy(self, request, *args, **kwargs):
        project = self.get_project()
        vendor = request.query_params.get("vendor")
        product = request.query_params.get("product") or None

        if not vendor:
            raise ValidationError({"vendor": "This field is required."})

        # Unsubscribe the project
        unsubscribe_project(
            project,
            vendor_name=vendor,
            product_name=product,
        )

        project.refresh_from_db()
        return self._subscriptions_response(project)


@extend_schema(tags=[TRACKER_TAG])
@extend_schema(parameters=ORG_PROJECT_PATH_PARAMS)
@extend_schema_view(
    list=extend_schema(summary="List CVEs tracked by a project."),
)
class ProjectCveViewSet(
    ViewSetMixin, ProjectScopedMixin, viewsets.GenericViewSet, mixins.ListModelMixin
):
    queryset = Cve.objects.none()
    scope_map = {
        "list": APIScope.TRACKER_READ,
    }

    def get_queryset(self):
        if self.is_schema_generation:
            return Cve.objects.none()
        project = self.get_project()
        vendors = _project_subscription_vendor_keys(project)
        if not vendors:
            return Cve.objects.none()

        # Get the CVEs that match the project subscriptions
        queryset = (
            Cve.objects.order_by("-updated_at")
            .filter(vendors__has_any_keys=vendors)
            .all()
        )

        # Optional filters: tracker status, assignee email
        status_filter = self.request.query_params.get("status")
        assignee = self.request.query_params.get("assignee")

        # Filter CVEs based on the status of the associated
        # tracker for the current project
        if status_filter:
            if status_filter == "no_status":
                project_trackers_with_status = CveTracker.objects.filter(
                    project=project, cve=OuterRef("pk")
                ).exclude(Q(status__isnull=True) | Q(status=""))
                queryset = queryset.annotate(
                    has_project_tracker_with_status=Exists(
                        project_trackers_with_status
                    ),
                ).filter(has_project_tracker_with_status=False)
            else:
                tracker_cves = CveTracker.objects.filter(
                    project=project, status=status_filter
                )
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

        # Validate the search query
        q = self.request.query_params.get("q")
        if q:
            search = Search(q, request=self.request)

            if not search.validate_parsing():
                raise ValidationError({"q": str(search.error)})

            try:
                queryset = queryset.filter(
                    id__in=search.query.values_list("id", flat=True)
                )
            except (BadQueryException, MaxFieldsExceededException) as exc:
                raise ValidationError({"q": str(exc)}) from exc

        return queryset

    def get_serializer_class(self):
        return CveListSerializer


@extend_schema(parameters=ORG_PROJECT_CVE_PATH_PARAMS)
@extend_schema_view(
    retrieve=extend_schema(
        summary="Retrieve a CVE tracked by a project.",
        tags=[TRACKER_TAG],
        responses={200: ProjectCveSerializer},
        examples=[PROJECT_CVE_DETAIL_RESPONSE_EXAMPLE],
    ),
    partial_update=extend_schema(
        summary="Update CVE tracker fields for a project.",
        tags=[TRACKER_TAG],
        request=CveTrackerUpdateSerializer,
        responses={200: ProjectCveSerializer},
        examples=[
            PROJECT_CVE_TRACKER_UPDATE_REQUEST_EXAMPLE,
            PROJECT_CVE_DETAIL_RESPONSE_EXAMPLE,
        ],
    ),
)
class ProjectCveDetailViewSet(ViewSetMixin, ProjectScopedMixin, viewsets.ViewSet):
    serializer_class = ProjectCveSerializer
    queryset = Cve.objects.none()
    scope_map = {
        "retrieve": APIScope.TRACKER_READ,
        "partial_update": APIScope.TRACKER_WRITE,
    }

    def retrieve(self, request, organization_name=None, project_name=None, cve_id=None):
        project = self.get_project()
        cve = get_object_or_404(Cve, cve_id=cve_id)

        # Check if the CVE matches the project subscriptions
        if not _cve_matches_project_subscriptions(project, cve):
            raise NotFound()

        # Associate the tracker with the CVE
        tracker = (
            CveTracker.objects.filter(project=project, cve=cve)
            .select_related("assignee")
            .first()
        )
        context = {"trackers": {cve.id: tracker} if tracker else {}}

        return Response(ProjectCveSerializer(cve, context=context).data)

    def partial_update(
        self, request, organization_name=None, project_name=None, cve_id=None
    ):
        project = self.get_project()
        cve = get_object_or_404(Cve, cve_id=cve_id)

        # Check if the CVE matches the project subscriptions
        if not _cve_matches_project_subscriptions(project, cve):
            raise NotFound()

        # Validate and update the tracker
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
        return Response(ProjectCveSerializer(cve, context=context).data)


@extend_schema(parameters=ORG_PROJECT_PATH_PARAMS, tags=[NOTIFICATIONS_TAG])
@extend_schema_view(
    list=extend_schema(summary="List notifications for a project."),
    create=extend_schema(
        summary="Create a notification for a project.",
        request=NotificationWriteSerializer,
        responses={201: NotificationSerializer},
        examples=[
            NOTIFICATION_CREATE_REQUEST_EXAMPLE,
            NOTIFICATION_RESPONSE_EXAMPLE,
        ],
    ),
    retrieve=extend_schema(
        summary="Retrieve a notification.",
        responses={200: NotificationSerializer},
        examples=[NOTIFICATION_RESPONSE_EXAMPLE],
    ),
    partial_update=extend_schema(
        summary="Update a notification.",
        request=NotificationWriteSerializer,
        responses={200: NotificationSerializer},
        examples=[
            NOTIFICATION_UPDATE_REQUEST_EXAMPLE,
            NOTIFICATION_RESPONSE_EXAMPLE,
        ],
    ),
    destroy=extend_schema(summary="Delete a notification."),
)
class NotificationViewSet(ViewSetMixin, ProjectScopedMixin, viewsets.ModelViewSet):
    serializer_class = NotificationSerializer
    queryset = Notification.objects.none()
    lookup_field = "name"
    lookup_url_kwarg = "notification_name"
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]
    scope_map = {
        "list": APIScope.NOTIFICATIONS_READ,
        "retrieve": APIScope.NOTIFICATIONS_READ,
        "create": APIScope.NOTIFICATIONS_WRITE,
        "partial_update": APIScope.NOTIFICATIONS_WRITE,
        "destroy": APIScope.NOTIFICATIONS_WRITE,
    }

    def get_serializer_class(self):
        if self.action in ("create", "partial_update", "update"):
            return NotificationWriteSerializer
        return NotificationSerializer

    def get_serializer_context(self):
        context = super().get_serializer_context()

        if self.action in ("create", "partial_update", "update"):
            context["project"] = self.get_project()

        return context

    def get_queryset(self):
        if self.is_schema_generation:
            return Notification.objects.none()

        project = self.get_project()
        return Notification.objects.filter(project=project).order_by("name")

    def perform_create(self, serializer):
        project = self.get_project()
        notification_type = serializer.validated_data["type"]
        configuration_input = serializer.validated_data.get("configuration", {})
        extras = build_notification_extras(notification_type, configuration_input)

        # Email notifications start disabled until the recipient confirms the address
        is_enabled = True
        if notification_type == "email":
            is_enabled = False
            extras["created_by_email"] = (
                getattr(self.request.api_actor, "email", "") or ""
            )
            extras["confirmation_token"] = secrets.token_urlsafe(32)

        # Save the notification
        notification = serializer.save(
            project=project,
            type=notification_type,
            configuration={"extras": extras},
            is_enabled=is_enabled,
        )

        # Send the notification confirmation email
        if notification_type == "email":
            send_notification_confirmation_email(notification, self.request)

    def perform_update(self, serializer):
        notification = serializer.instance
        configuration_input = serializer.validated_data.get("configuration")
        email_changed = False
        save_kwargs = {}

        # Validate and update the notification
        if configuration_input is not None:
            existing_extras = (notification.configuration or {}).get("extras") or {}

            extras = build_notification_extras(
                notification.type,
                configuration_input,
                existing_extras=existing_extras,
            )

            if notification.type == "email":
                config = normalize_configuration_input(configuration_input)

                if "email" in config:
                    new_email = extras.get("email")
                    old_email = existing_extras.get("email")
                    if new_email != old_email:

                        # Changing the email address requires re-confirmation.
                        extras["confirmation_token"] = secrets.token_urlsafe(32)
                        extras.pop("unsubscribe_token", None)
                        email_changed = bool(new_email)
                        save_kwargs["is_enabled"] = False
            save_kwargs["configuration"] = {"extras": extras}

        # Save the notification
        serializer.save(**save_kwargs)

        if email_changed:
            send_notification_confirmation_email(notification, self.request)


@extend_schema(tags=[AUTOMATIONS_TAG])
@extend_schema(parameters=ORG_PROJECT_PATH_PARAMS)
@extend_schema_view(
    list=extend_schema(summary="List automations for a project."),
    create=extend_schema(
        summary="Create an automation for a project.",
        request=AutomationWriteSerializer,
        responses={201: AutomationSerializer},
        examples=[
            AUTOMATION_CREATE_REQUEST_EXAMPLE,
            AUTOMATION_CREATE_RESPONSE_EXAMPLE,
        ],
    ),
    retrieve=extend_schema(
        summary="Retrieve an automation.",
        responses={200: AutomationSerializer},
        examples=[AUTOMATION_DETAIL_RESPONSE_EXAMPLE],
    ),
    partial_update=extend_schema(
        summary="Update an automation.",
        request=AutomationWriteSerializer,
        responses={200: AutomationSerializer},
        examples=[
            AUTOMATION_UPDATE_REQUEST_EXAMPLE,
            AUTOMATION_UPDATE_RESPONSE_EXAMPLE,
        ],
    ),
    destroy=extend_schema(summary="Delete an automation."),
)
class AutomationViewSet(ViewSetMixin, ProjectScopedMixin, viewsets.ModelViewSet):
    lookup_field = "name"
    queryset = Automation.objects.none()
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]
    scope_map = {
        "list": APIScope.AUTOMATIONS_READ,
        "retrieve": APIScope.AUTOMATIONS_READ,
        "create": APIScope.AUTOMATIONS_WRITE,
        "partial_update": APIScope.AUTOMATIONS_WRITE,
        "destroy": APIScope.AUTOMATIONS_WRITE,
    }

    def get_serializer_class(self):
        if self.action == "list":
            return AutomationListSerializer

        if self.action in ("create", "partial_update", "update"):
            return AutomationWriteSerializer

        return AutomationSerializer

    def get_serializer_context(self):
        context = super().get_serializer_context()

        if self.action in ("create", "partial_update", "update"):
            context["project"] = self.get_project()

        return context

    def get_queryset(self):
        if self.is_schema_generation:
            return Automation.objects.none()

        project = self.get_project()
        return Automation.objects.filter(project=project).order_by("name")

    def perform_create(self, serializer):
        project = self.get_project()
        serializer.save(project=project)

    def create(self, request, *args, **kwargs):
        serializer = AutomationWriteSerializer(
            data=request.data,
            context=self.get_serializer_context(),
        )

        # Validate and save the automation
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        return Response(
            AutomationSerializer(serializer.instance).data,
            status=status.HTTP_201_CREATED,
        )

    def partial_update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = AutomationWriteSerializer(
            instance,
            data=request.data,
            partial=True,
            context=self.get_serializer_context(),
        )

        # Validate and save the automation
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(AutomationSerializer(instance).data)


@extend_schema(tags=[AUTOMATIONS_TAG])
@extend_schema(parameters=ORG_PROJECT_AUTOMATION_PATH_PARAMS)
@extend_schema_view(
    list=extend_schema(summary="List execution history for an automation."),
    retrieve=extend_schema(
        summary="Retrieve an automation execution.",
        responses={200: AutomationExecutionDetailSerializer},
        examples=[AUTOMATION_EXECUTION_DETAIL_RESPONSE_EXAMPLE],
    ),
)
class AutomationExecutionViewSet(
    ViewSetMixin, ProjectScopedMixin, viewsets.ReadOnlyModelViewSet
):
    serializer_class = AutomationExecutionSerializer
    queryset = AutomationExecution.objects.none()
    lookup_field = "id"
    lookup_url_kwarg = "execution_id"
    scope_map = {
        "list": APIScope.AUTOMATIONS_READ,
        "retrieve": APIScope.AUTOMATIONS_READ,
    }

    def _automation_name(self):
        return self.kwargs["automation_name"]

    def get_queryset(self):
        if self.is_schema_generation:
            return AutomationExecution.objects.none()

        # Check if the automation exists in the project
        project = self.get_project()
        automation = get_object_or_404(
            Automation,
            project=project,
            name=self._automation_name(),
        )

        return AutomationExecution.objects.filter(automation=automation).order_by(
            "-executed_at"
        )

    def retrieve(self, request, *args, **kwargs):
        execution = self.get_object()

        # Get the automation execution details
        data = AutomationExecutionDetailSerializer(execution).data
        data["results"] = AutomationRunResultSerializer(
            AutomationRunResult.objects.filter(automation_execution=execution),
            many=True,
        ).data

        return Response(data)


@extend_schema(tags=[REPORTS_TAG])
@extend_schema(parameters=ORG_PROJECT_PATH_PARAMS)
@extend_schema_view(
    list=extend_schema(
        summary="List reports for a project.",
        examples=[REPORT_LIST_ITEM_EXAMPLE],
    ),
    retrieve=extend_schema(
        summary="Retrieve a report.",
        parameters=ORG_PROJECT_REPORT_PATH_PARAMS,
        responses={200: ReportDetailSerializer},
        examples=[REPORT_DETAIL_RESPONSE_EXAMPLE],
    ),
)
class ReportViewSet(ViewSetMixin, ProjectScopedMixin, viewsets.ReadOnlyModelViewSet):
    serializer_class = ReportSerializer
    queryset = Report.objects.none()
    lookup_field = "id"
    lookup_url_kwarg = "report_id"
    scope_map = {
        "list": APIScope.REPORTS_READ,
        "retrieve": APIScope.REPORTS_READ,
    }

    def get_queryset(self):
        if self.is_schema_generation:
            return Report.objects.none()

        # Get the reports for the project
        project = self.get_project()
        changes_prefetch = Prefetch(
            "changes",
            queryset=Change.objects.select_related("cve"),
        )
        queryset = (
            Report.objects.filter(project=project)
            .prefetch_related(changes_prefetch)
            .order_by("-day")
        )

        # Filter the reports by period type
        period = self.request.query_params.get("period_type")
        if period in ("daily", "weekly"):
            queryset = queryset.filter(period_type=period)

        return queryset

    def get_serializer_class(self):
        if self.action == "retrieve":
            return ReportDetailSerializer

        return ReportSerializer
