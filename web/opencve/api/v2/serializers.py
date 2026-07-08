from rest_framework import serializers

from django.core.exceptions import ValidationError as DjangoValidationError

from cves.models import Cve, Product, Vendor, Weakness
from cves.serializers import DateTimeWithoutMicrosecondsField
from drf_spectacular.utils import extend_schema_field, extend_schema_serializer
from changes.models import Change, Report
from organizations.models import Membership, Organization
from organizations.services.organizations import validate_organization_name
from projects.models import (
    Automation,
    AutomationExecution,
    AutomationRunResult,
    CveTracker,
    Notification,
    Project,
)
from projects.services.automations import (
    AUTOMATION_WRITE_FIELDS,
    validate_and_normalize_automation_write,
)
from projects.services.notifications import safe_notification_configuration
from projects.utils import report_unique_cves, report_unique_cves_count
from projects.services.notifications import (
    validate_notification_name,
    validate_notification_write_configuration,
)
from projects.services.projects import validate_project_name
from projects.services.subscriptions import subscriptions_to_api_format_from_project
from opencve.api.v2.openapi import (
    AUDIT_LOG_LIST_ITEM_EXAMPLE,
    AUTOMATION_EXECUTION_LIST_ITEM_EXAMPLE,
    AUTOMATION_LIST_ITEM_EXAMPLE,
    CVE_LIST_ITEM_EXAMPLE,
    NOTIFICATION_LIST_ITEM_EXAMPLE,
    ORGANIZATION_LIST_ITEM_EXAMPLE,
    ORGANIZATION_UPDATE_REQUEST_EXAMPLE,
    ORGANIZATION_UPDATE_RESPONSE_EXAMPLE,
    PROJECT_LIST_ITEM_EXAMPLE,
    VENDOR_LIST_ITEM_EXAMPLE,
    PRODUCT_LIST_ITEM_EXAMPLE,
    WEAKNESS_LIST_ITEM_EXAMPLE,
)


@extend_schema_serializer(
    component_name="ApiWeaknessList",
    examples=[WEAKNESS_LIST_ITEM_EXAMPLE],
)
class WeaknessSerializer(serializers.ModelSerializer):
    created_at = DateTimeWithoutMicrosecondsField(read_only=True)
    updated_at = DateTimeWithoutMicrosecondsField(read_only=True)

    class Meta:
        model = Weakness
        fields = ["created_at", "updated_at", "cwe_id", "name", "description"]


@extend_schema_serializer(
    component_name="ApiCveList",
    examples=[CVE_LIST_ITEM_EXAMPLE],
)
class CveListSerializer(serializers.ModelSerializer):
    created_at = DateTimeWithoutMicrosecondsField(read_only=True)
    updated_at = DateTimeWithoutMicrosecondsField(read_only=True)

    class Meta:
        model = Cve
        fields = ["created_at", "updated_at", "cve_id", "description", "title"]


@extend_schema_serializer(
    component_name="ApiVendorList",
    examples=[VENDOR_LIST_ITEM_EXAMPLE],
)
class VendorListSerializer(serializers.ModelSerializer):
    created_at = DateTimeWithoutMicrosecondsField(read_only=True)
    updated_at = DateTimeWithoutMicrosecondsField(read_only=True)

    class Meta:
        model = Vendor
        fields = ["created_at", "updated_at", "name"]


@extend_schema_serializer(
    component_name="ApiProductList",
    examples=[PRODUCT_LIST_ITEM_EXAMPLE],
)
class ProductListSerializer(serializers.ModelSerializer):
    created_at = DateTimeWithoutMicrosecondsField(read_only=True)
    updated_at = DateTimeWithoutMicrosecondsField(read_only=True)

    class Meta:
        model = Product
        fields = ["created_at", "updated_at", "name"]


@extend_schema_serializer(component_name="ApiCveDetail")
class CveDetailSerializer(CveListSerializer):
    class Meta(CveListSerializer.Meta):
        fields = CveListSerializer.Meta.fields + [
            "metrics",
            "weaknesses",
            "vendors",
        ]


class TrackerSerializer(serializers.ModelSerializer):
    assignee = serializers.SerializerMethodField()

    class Meta:
        model = CveTracker
        fields = ["status", "assignee", "assigned_at", "updated_at"]

    @staticmethod
    @extend_schema_field(
        {"type": "object", "nullable": True, "properties": {"email": {}}}
    )
    def get_assignee(obj):
        if not obj.assignee_id:
            return None
        return {"email": obj.assignee.email}


@extend_schema_serializer(component_name="ApiProjectCve")
class ProjectCveSerializer(CveListSerializer):
    tracker = serializers.SerializerMethodField()

    class Meta(CveListSerializer.Meta):
        fields = CveListSerializer.Meta.fields + ["metrics", "tracker"]

    @extend_schema_field({"type": "object", "nullable": True})
    def get_tracker(self, obj):
        tracker = self.context.get("trackers", {}).get(obj.id)
        if not tracker:
            return None
        return TrackerSerializer(tracker).data


@extend_schema_serializer(
    component_name="ApiOrganization",
    examples=[ORGANIZATION_LIST_ITEM_EXAMPLE],
)
class OrganizationSerializer(serializers.ModelSerializer):
    name = serializers.CharField(
        max_length=100,
        help_text="Organization slug (e.g. `acme`).",
    )
    members_count = serializers.SerializerMethodField()
    projects_count = serializers.SerializerMethodField()

    class Meta:
        model = Organization
        fields = [
            "id",
            "created_at",
            "updated_at",
            "name",
            "members_count",
            "projects_count",
        ]
        read_only_fields = [
            "id",
            "created_at",
            "updated_at",
            "members_count",
            "projects_count",
        ]

    @staticmethod
    @extend_schema_field({"type": "integer", "example": 3})
    def get_members_count(obj):
        return obj.get_members().count()

    @staticmethod
    @extend_schema_field({"type": "integer", "example": 5})
    def get_projects_count(obj):
        return obj.projects.count()


@extend_schema_serializer(
    examples=[PROJECT_LIST_ITEM_EXAMPLE],
)
class ProjectSerializer(serializers.ModelSerializer):
    subscriptions_count = serializers.IntegerField(read_only=True, required=False)

    class Meta:
        model = Project
        fields = [
            "id",
            "created_at",
            "updated_at",
            "name",
            "description",
            "active",
            "subscriptions_count",
        ]
        read_only_fields = ["id", "created_at", "updated_at", "subscriptions_count"]


class ProjectWriteSerializer(serializers.ModelSerializer):
    """Request body for creating or updating a project (v2 write)."""

    name = serializers.CharField(
        max_length=100,
        help_text="Project slug: letters, digits, and dashes only (e.g. `production`).",
    )
    description = serializers.CharField(
        required=False,
        allow_blank=True,
        allow_null=True,
        help_text="Optional project description.",
    )
    active = serializers.BooleanField(
        required=False,
        default=True,
        help_text="Whether the project is active (default: true).",
    )

    class Meta:
        model = Project
        fields = ["name", "description", "active"]

    def validate_name(self, value):
        organization = self.context.get("organization")
        if organization is None:
            return value
        try:
            validate_project_name(
                value,
                organization=organization,
                exclude_project=self.instance,
            )
        except DjangoValidationError as exc:
            raise serializers.ValidationError(list(exc.messages)) from exc
        return value


@extend_schema_serializer(
    examples=[ORGANIZATION_UPDATE_REQUEST_EXAMPLE],
)
class OrganizationWriteSerializer(serializers.ModelSerializer):
    """Request body for updating an organization."""

    name = serializers.CharField(
        max_length=100,
        help_text="Organization slug: letters, digits, and dashes only (e.g. `acme-corp`).",
    )

    class Meta:
        model = Organization
        fields = ["name"]

    def validate_name(self, value):
        try:
            validate_organization_name(value, exclude_organization=self.instance)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(list(exc.messages)) from exc
        return value


class ProjectDetailSerializer(ProjectSerializer):
    subscriptions = serializers.SerializerMethodField()

    class Meta(ProjectSerializer.Meta):
        fields = ProjectSerializer.Meta.fields + ["subscriptions"]

    @staticmethod
    @extend_schema_field({"type": "object"})
    def get_subscriptions(instance):
        return subscriptions_to_api_format_from_project(instance)


class SubscriptionListSerializer(serializers.Serializer):
    """Project subscriptions payload (vendors + products grouped by vendor)."""

    vendors = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        default=list,
    )
    products = serializers.DictField(
        child=serializers.ListField(child=serializers.CharField()),
        required=False,
        default=dict,
    )


class SubscriptionMutationSerializer(serializers.Serializer):
    vendor = serializers.CharField(required=True)
    product = serializers.CharField(required=False, allow_blank=True)


class CveTrackerUpdateSerializer(serializers.Serializer):
    status = serializers.ChoiceField(
        choices=[c[0] for c in CveTracker.STATUS_CHOICES],
        required=False,
        allow_null=True,
    )
    assignee = serializers.EmailField(required=False, allow_null=True)


@extend_schema_serializer(examples=[NOTIFICATION_LIST_ITEM_EXAMPLE])
class NotificationSerializer(serializers.ModelSerializer):
    configuration = serializers.SerializerMethodField()
    is_pending_email_confirmation = serializers.SerializerMethodField()

    class Meta:
        model = Notification
        fields = [
            "id",
            "created_at",
            "updated_at",
            "name",
            "type",
            "is_enabled",
            "configuration",
            "is_pending_email_confirmation",
        ]

    @extend_schema_field({"type": "object"})
    def get_configuration(self, obj):
        extras = (obj.configuration or {}).get("extras") or {}
        return safe_notification_configuration(obj.type, extras)

    @extend_schema_field({"type": "boolean", "nullable": True})
    def get_is_pending_email_confirmation(self, obj):
        if obj.type != "email":
            return None
        return obj.is_pending_email_confirmation

    def to_representation(self, instance):
        data = super().to_representation(instance)
        if data.get("is_pending_email_confirmation") is None:
            data.pop("is_pending_email_confirmation", None)
        return data


class NotificationWriteSerializer(serializers.ModelSerializer):
    configuration = serializers.JSONField(required=False, write_only=True)

    class Meta:
        model = Notification
        fields = ["name", "type", "is_enabled", "configuration"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance is not None:
            self.fields["type"].read_only = True

    def validate_type(self, value):
        if value not in ("email", "webhook", "slack"):
            raise serializers.ValidationError("Must be email, webhook, or slack.")
        return value

    def validate_name(self, value):
        project = self.context.get("project")
        try:
            validate_notification_name(
                value,
                project=project,
                exclude_notification=self.instance,
            )
        except DjangoValidationError as exc:
            raise serializers.ValidationError(list(exc.messages)) from exc
        return value

    def validate_configuration(self, value):
        if value is None:
            value = {}
        notification_type = (
            self.initial_data.get("type")
            if self.instance is None
            else self.instance.type
        )
        if not notification_type:
            return value
        try:
            validate_notification_write_configuration(
                notification_type,
                value,
                require_values=self.instance is None,
            )
        except DjangoValidationError as exc:
            raise serializers.ValidationError(list(exc.messages)) from exc
        return value

    def validate(self, attrs):
        # On create without an explicit configuration payload, still validate that
        # the notification type's required fields would be satisfiable.
        if self.instance is None and "configuration" not in attrs:
            notification_type = attrs.get("type")
            if notification_type:
                try:
                    validate_notification_write_configuration(
                        notification_type,
                        {},
                        require_values=True,
                    )
                except DjangoValidationError as exc:
                    raise serializers.ValidationError(
                        {"configuration": list(exc.messages)}
                    ) from exc
        return attrs

    def to_representation(self, instance):
        return NotificationSerializer(instance, context=self.context).data


@extend_schema_serializer(examples=[AUTOMATION_LIST_ITEM_EXAMPLE])
class AutomationListSerializer(serializers.ModelSerializer):
    conditions_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = Automation
        fields = [
            "id",
            "created_at",
            "updated_at",
            "name",
            "is_enabled",
            "trigger_type",
            "frequency",
            "schedule_timezone",
            "schedule_time",
            "schedule_weekday",
            "last_execution_at",
            "conditions_count",
        ]


class AutomationSerializer(AutomationListSerializer):
    class Meta(AutomationListSerializer.Meta):
        fields = AutomationListSerializer.Meta.fields + ["configuration"]


class AutomationWriteSerializer(serializers.ModelSerializer):
    """Request body for creating or updating an automation (v2 write)."""

    configuration = serializers.JSONField(required=False)

    class Meta:
        model = Automation
        fields = list(AUTOMATION_WRITE_FIELDS)

    def validate(self, attrs):
        project = self.context.get("project")
        if project is None:
            raise serializers.ValidationError("Project context is required.")

        if not self.partial and "configuration" not in attrs:
            raise serializers.ValidationError(
                {"configuration": ["This field is required."]}
            )

        try:
            return validate_and_normalize_automation_write(
                attrs,
                project=project,
                instance=self.instance,
                partial=self.partial,
            )
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.message_dict) from exc


@extend_schema_serializer(examples=[AUTOMATION_EXECUTION_LIST_ITEM_EXAMPLE])
class AutomationExecutionSerializer(serializers.ModelSerializer):
    class Meta:
        model = AutomationExecution
        fields = [
            "id",
            "created_at",
            "executed_at",
            "window_start",
            "window_end",
            "matched_cves_count",
            "impact_summary",
            "cves_table_data",
        ]


class AutomationRunResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = AutomationRunResult
        fields = ["id", "output_type", "label", "status", "details", "created_at"]


class AutomationExecutionDetailSerializer(AutomationExecutionSerializer):
    results = AutomationRunResultSerializer(many=True, read_only=True)

    class Meta(AutomationExecutionSerializer.Meta):
        fields = AutomationExecutionSerializer.Meta.fields + ["results"]


class ReportSerializer(serializers.ModelSerializer):
    cves_count = serializers.SerializerMethodField()

    class Meta:
        model = Report
        fields = [
            "id",
            "created_at",
            "updated_at",
            "day",
            "period_type",
            "period_timezone",
            "cves_count",
        ]

    @staticmethod
    @extend_schema_field(serializers.IntegerField())
    def get_cves_count(obj):
        return report_unique_cves_count(obj.changes.all())


class ReportAiSummarySerializer(serializers.Serializer):
    html = serializers.CharField()


class ReportDetailSerializer(ReportSerializer):
    ai_summary = serializers.SerializerMethodField()
    cves = serializers.SerializerMethodField()

    class Meta(ReportSerializer.Meta):
        fields = ReportSerializer.Meta.fields + ["ai_summary", "cves"]

    @staticmethod
    @extend_schema_field(ReportAiSummarySerializer(allow_null=True))
    def get_ai_summary(obj):
        if not obj.ai_summary or not obj.ai_summary.strip():
            return None
        return {"html": obj.ai_summary}

    @staticmethod
    @extend_schema_field(CveListSerializer(many=True))
    def get_cves(obj):
        return CveListSerializer(report_unique_cves(obj.changes.all()), many=True).data


class MembershipSerializer(serializers.ModelSerializer):
    email = serializers.SerializerMethodField()
    is_invited = serializers.BooleanField(read_only=True)

    class Meta:
        model = Membership
        fields = [
            "id",
            "role",
            "email",
            "date_invited",
            "date_joined",
            "is_invited",
        ]

    @staticmethod
    @extend_schema_field(serializers.EmailField())
    def get_email(obj):
        if obj.user_id:
            return obj.user.email
        return obj.email


@extend_schema_serializer(examples=[AUDIT_LOG_LIST_ITEM_EXAMPLE])
class AuditLogEntrySerializer(serializers.Serializer):
    id = serializers.IntegerField()
    timestamp = serializers.DateTimeField()
    action = serializers.IntegerField()
    actor = serializers.CharField(allow_null=True)
    resource = serializers.CharField(allow_null=True)
    object_repr = serializers.CharField(allow_null=True)
    changes = serializers.JSONField(allow_null=True)


class MembershipCreateSerializer(serializers.Serializer):
    email = serializers.EmailField()
    role = serializers.ChoiceField(choices=Membership.ROLES)


class MembershipUpdateSerializer(serializers.Serializer):
    role = serializers.ChoiceField(choices=Membership.ROLES)


@extend_schema_serializer(
    component_name="CveChangeList",
)
class ChangeListSerializer(serializers.ModelSerializer):
    cve_id = serializers.CharField(source="cve.cve_id", read_only=True)

    class Meta:
        model = Change
        fields = ["id", "created_at", "updated_at", "cve_id", "types"]


@extend_schema_serializer(component_name="CveChangeDetail")
class ChangeDetailSerializer(ChangeListSerializer):
    change_data = serializers.SerializerMethodField()

    class Meta(ChangeListSerializer.Meta):
        fields = ChangeListSerializer.Meta.fields + ["change_data"]

    @staticmethod
    @extend_schema_field({"type": "object"})
    def get_change_data(obj):
        try:
            return obj.change_data
        except (FileNotFoundError, OSError, KeyError):
            return {}
