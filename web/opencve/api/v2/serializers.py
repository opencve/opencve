from rest_framework import serializers

from cves.models import Cve, Product, Vendor, Weakness
from cves.serializers import DateTimeWithoutMicrosecondsField
from drf_spectacular.utils import extend_schema_serializer
from changes.models import Change, Report
from dashboards.models import Dashboard
from organizations.models import Membership, Organization, OrganizationAPIToken
from projects.models import (
    Automation,
    AutomationExecution,
    AutomationRunResult,
    CveComment,
    CveTracker,
    Notification,
    Project,
)
from users.models import CveTag, UserTag
from views.models import View

from opencve.api.v2.openapi import (
    ORGANIZATION_CREATE_EXAMPLE,
    ORGANIZATION_UPDATE_EXAMPLE,
    PROJECT_CREATE_EXAMPLE,
    PROJECT_UPDATE_EXAMPLE,
)


class WeaknessSerializerV2(serializers.ModelSerializer):
    created_at = DateTimeWithoutMicrosecondsField(read_only=True)
    updated_at = DateTimeWithoutMicrosecondsField(read_only=True)

    class Meta:
        model = Weakness
        fields = ["created_at", "updated_at", "cwe_id", "name", "description"]


class CveListSerializerV2(serializers.ModelSerializer):
    created_at = DateTimeWithoutMicrosecondsField(read_only=True)
    updated_at = DateTimeWithoutMicrosecondsField(read_only=True)

    class Meta:
        model = Cve
        fields = ["created_at", "updated_at", "cve_id", "description", "title"]


class CveDetailSerializerV2(CveListSerializerV2):
    class Meta(CveListSerializerV2.Meta):
        fields = CveListSerializerV2.Meta.fields + [
            "metrics",
            "weaknesses",
            "vendors",
        ]


class TrackerSerializerV2(serializers.ModelSerializer):
    assignee = serializers.SerializerMethodField()

    class Meta:
        model = CveTracker
        fields = ["status", "assignee", "assigned_at", "updated_at"]

    @staticmethod
    def get_assignee(obj):
        if not obj.assignee_id:
            return None
        return {"id": obj.assignee_id, "email": obj.assignee.email}


class ProjectCveSerializerV2(CveListSerializerV2):
    tracker = serializers.SerializerMethodField()

    class Meta(CveListSerializerV2.Meta):
        fields = CveListSerializerV2.Meta.fields + ["metrics", "tracker"]

    def get_tracker(self, obj):
        tracker = self.context.get("trackers", {}).get(obj.id)
        if not tracker:
            return None
        return TrackerSerializerV2(tracker).data


class OrganizationSerializerV2(serializers.ModelSerializer):
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
    def get_members_count(obj):
        return obj.get_members().count()

    @staticmethod
    def get_projects_count(obj):
        return obj.projects.count()


class ProjectSerializerV2(serializers.ModelSerializer):
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


@extend_schema_serializer(
    examples=[PROJECT_CREATE_EXAMPLE, PROJECT_UPDATE_EXAMPLE],
)
class ProjectWriteSerializerV2(serializers.ModelSerializer):
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


@extend_schema_serializer(
    examples=[ORGANIZATION_CREATE_EXAMPLE, ORGANIZATION_UPDATE_EXAMPLE],
)
class OrganizationWriteSerializerV2(serializers.ModelSerializer):
    """Request body for creating or updating an organization (v2 write)."""

    name = serializers.CharField(
        max_length=100,
        help_text="Organization slug: letters, digits, and dashes only (e.g. `acme-corp`).",
    )

    class Meta:
        model = Organization
        fields = ["name"]


class ProjectDetailSerializerV2(ProjectSerializerV2):
    subscriptions = serializers.SerializerMethodField()
    stats = serializers.SerializerMethodField()

    class Meta(ProjectSerializerV2.Meta):
        fields = ProjectSerializerV2.Meta.fields + ["subscriptions", "stats"]

    @staticmethod
    def get_subscriptions(instance):
        from cves.constants import PRODUCT_SEPARATOR

        subscriptions = {"vendors": instance.subscriptions["vendors"], "products": {}}
        for product in instance.subscriptions["products"]:
            v_name, p_name = product.split(PRODUCT_SEPARATOR)
            subscriptions["products"].setdefault(v_name, []).append(p_name)
        return subscriptions

    @staticmethod
    def get_stats(instance):
        trackers = instance.cve_trackers.exclude(status__isnull=True).exclude(status="")
        return {
            "tracked_cves": instance.cve_trackers.count(),
            "open_trackers": trackers.exclude(
                status__in=["resolved", "not_applicable", "risk_accepted"]
            ).count(),
        }


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


class CveCommentSerializerV2(serializers.ModelSerializer):
    author = serializers.SerializerMethodField()
    replies = serializers.SerializerMethodField()

    class Meta:
        model = CveComment
        fields = [
            "id",
            "created_at",
            "updated_at",
            "body",
            "edited",
            "author",
            "replies",
        ]

    @staticmethod
    def get_author(obj):
        return {"id": obj.author_id, "email": obj.author.email}

    def get_replies(self, obj):
        if obj.parent_id:
            return []
        replies = obj.replies.all()
        return CveCommentSerializerV2(replies, many=True, context=self.context).data


class NotificationSerializerV2(serializers.ModelSerializer):
    is_pending_email_confirmation = serializers.BooleanField(read_only=True)

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


class AutomationSerializerV2(serializers.ModelSerializer):
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
            "configuration",
            "conditions_count",
        ]


class AutomationExecutionSerializerV2(serializers.ModelSerializer):
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


class AutomationRunResultSerializerV2(serializers.ModelSerializer):
    class Meta:
        model = AutomationRunResult
        fields = ["id", "output_type", "label", "status", "details", "created_at"]


class ReportSerializerV2(serializers.ModelSerializer):
    class Meta:
        model = Report
        fields = [
            "id",
            "created_at",
            "updated_at",
            "day",
            "period_type",
            "period_timezone",
            "seen",
            "ai_summary",
        ]


class ReportDetailSerializerV2(ReportSerializerV2):
    changes_count = serializers.SerializerMethodField()

    class Meta(ReportSerializerV2.Meta):
        fields = ReportSerializerV2.Meta.fields + ["changes_count"]

    @staticmethod
    def get_changes_count(obj):
        return obj.changes.count()


class MembershipSerializerV2(serializers.ModelSerializer):
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
    def get_email(obj):
        if obj.user_id:
            return obj.user.email
        return obj.email


class MembershipCreateSerializer(serializers.Serializer):
    email = serializers.EmailField()
    role = serializers.ChoiceField(choices=Membership.ROLES)


class MembershipUpdateSerializer(serializers.Serializer):
    role = serializers.ChoiceField(choices=Membership.ROLES)


class OrganizationTokenSerializerV2(serializers.ModelSerializer):
    class Meta:
        model = OrganizationAPIToken
        fields = [
            "token_id",
            "name",
            "description",
            "access_mode",
            "scopes",
            "is_active",
            "created_at",
            "last_used_at",
        ]


class OrganizationTokenCreateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=100)
    description = serializers.CharField(
        max_length=255, required=False, allow_blank=True
    )
    access_mode = serializers.ChoiceField(
        choices=OrganizationAPIToken.AccessMode.choices,
        default=OrganizationAPIToken.AccessMode.READ,
    )
    scopes = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        default=list,
    )


class SavedViewSerializerV2(serializers.ModelSerializer):
    class Meta:
        model = View
        fields = ["id", "created_at", "updated_at", "name", "query", "privacy"]


class UserTagSerializerV2(serializers.ModelSerializer):
    class Meta:
        model = UserTag
        fields = ["id", "created_at", "updated_at", "name", "color", "description"]


class CveTagsUpdateSerializer(serializers.Serializer):
    tags = serializers.ListField(child=serializers.CharField(), allow_empty=True)


class DashboardSerializerV2(serializers.ModelSerializer):
    class Meta:
        model = Dashboard
        fields = ["id", "created_at", "updated_at", "name", "config", "is_default"]


class ChangeListSerializerV2(serializers.ModelSerializer):
    cve_id = serializers.CharField(source="cve.cve_id", read_only=True)

    class Meta:
        model = Change
        fields = ["id", "created_at", "updated_at", "cve_id", "types"]


class ChangeDetailSerializerV2(ChangeListSerializerV2):
    change_data = serializers.SerializerMethodField()

    class Meta(ChangeListSerializerV2.Meta):
        fields = ChangeListSerializerV2.Meta.fields + ["change_data"]

    @staticmethod
    def get_change_data(obj):
        try:
            return obj.change_data
        except (FileNotFoundError, OSError, KeyError):
            return {}
