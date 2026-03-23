import importlib

from django.core.validators import RegexValidator
from django.db import models
from django.urls import reverse

from opencve.models import BaseModel
from opencve.validators import slug_regex_validator
from organizations.models import Organization


def get_default_subscriptions():
    return dict(vendors=[], products=[])


def get_default_configuration():
    # Kept for historical migrations that import this symbol.
    return {"extras": {}}


def get_default_automation_config():
    return {"conditions": {"operator": "OR", "children": []}, "actions": []}


def count_conditions_tree(node):
    """
    Count leaf conditions in a conditions tree.
    Nodes with "children" are groups (OR/AND); nodes with "type" are actual conditions.
    """
    if not node:
        return 0
    if "children" in node:
        return sum(count_conditions_tree(c) for c in node.get("children", []))
    if "type" in node:
        return 1
    return 0


class Project(BaseModel):
    name = models.CharField(
        max_length=100,
        validators=[slug_regex_validator],
    )
    description = models.TextField(blank=True, null=True)
    subscriptions = models.JSONField(default=get_default_subscriptions)
    active = models.BooleanField(default=True)

    # Relationships
    organization = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name="projects"
    )

    class Meta:
        db_table = "opencve_projects"
        constraints = [
            models.UniqueConstraint(
                fields=["name", "organization_id"],
                name="ix_unique_organization_project_name",
            )
        ]

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse(
            "project",
            kwargs={"project_name": self.name, "org_name": self.organization.name},
        )

    @property
    def subscriptions_count(self):
        return len(self.subscriptions["vendors"]) + len(self.subscriptions["products"])


class Notification(BaseModel):
    name = models.CharField(
        max_length=256,
        validators=[
            RegexValidator(
                regex=r"^[a-zA-Z0-9\-_ ]+$",
                message="Special characters (except dash and underscore) are not accepted",
            ),
        ],
    )
    type = models.CharField(max_length=64)
    is_enabled = models.BooleanField(default=True)
    configuration = models.JSONField(default=get_default_configuration)
    _notification = None

    # Relationships
    project = models.ForeignKey(
        Project, on_delete=models.CASCADE, related_name="notifications"
    )

    class Meta:
        db_table = "opencve_notifications"

    def __str__(self):
        return f"{self.name} ({self.project.name})"

    @property
    def notification(self):
        if not self._notification:
            self._notification = getattr(
                importlib.import_module(f"projects.notifications.{self.type}"),
                f"{self.type}Notification",
            )(self.configuration)
        return self._notification

    def get_absolute_url(self):
        return reverse(
            "notifications",
            kwargs={
                "project_name": self.project.name,
                "org_name": self.project.organization.name,
            },
        )

    @property
    def is_pending_email_confirmation(self):
        """True when type is email and subscription is not yet confirmed."""
        if self.type != "email":
            return False
        extras = self.configuration.get("extras") or {}
        return bool(extras.get("confirmation_token"))


class Automation(BaseModel):
    TRIGGER_REALTIME = "realtime"
    TRIGGER_SCHEDULED = "scheduled"
    TRIGGER_CHOICES = [
        (TRIGGER_REALTIME, "Real-time monitoring"),
        (TRIGGER_SCHEDULED, "Scheduled report"),
    ]
    FREQUENCY_DAILY = "daily"
    FREQUENCY_WEEKLY = "weekly"
    FREQUENCY_CHOICES = [
        (FREQUENCY_DAILY, "Daily"),
        (FREQUENCY_WEEKLY, "Weekly"),
    ]
    WEEKDAY_MONDAY = "monday"
    WEEKDAY_TUESDAY = "tuesday"
    WEEKDAY_WEDNESDAY = "wednesday"
    WEEKDAY_THURSDAY = "thursday"
    WEEKDAY_FRIDAY = "friday"
    WEEKDAY_SATURDAY = "saturday"
    WEEKDAY_SUNDAY = "sunday"
    WEEKDAY_CHOICES = [
        (WEEKDAY_MONDAY, "Monday"),
        (WEEKDAY_TUESDAY, "Tuesday"),
        (WEEKDAY_WEDNESDAY, "Wednesday"),
        (WEEKDAY_THURSDAY, "Thursday"),
        (WEEKDAY_FRIDAY, "Friday"),
        (WEEKDAY_SATURDAY, "Saturday"),
        (WEEKDAY_SUNDAY, "Sunday"),
    ]

    name = models.CharField(
        max_length=256,
        validators=[
            RegexValidator(
                regex=r"^[a-zA-Z0-9\-_ ]+$",
                message="Special characters (except dash and underscore) are not accepted",
            ),
        ],
    )
    is_enabled = models.BooleanField(default=True)
    trigger_type = models.CharField(
        max_length=20,
        choices=TRIGGER_CHOICES,
        default=TRIGGER_REALTIME,
    )
    frequency = models.CharField(
        max_length=20,
        choices=FREQUENCY_CHOICES,
        null=True,
        blank=True,
    )
    schedule_timezone = models.CharField(max_length=64, null=True, blank=True)
    schedule_time = models.TimeField(null=True, blank=True)
    schedule_weekday = models.CharField(
        max_length=20,
        choices=WEEKDAY_CHOICES,
        null=True,
        blank=True,
    )
    configuration = models.JSONField(default=get_default_automation_config)

    # Relationships
    project = models.ForeignKey(
        Project, on_delete=models.CASCADE, related_name="automations"
    )

    class Meta:
        db_table = "opencve_automations"

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse(
            "automation_overview",
            kwargs={
                "project_name": self.project.name,
                "org_name": self.project.organization.name,
                "automation": self.name,
            },
        )

    @property
    def conditions_count(self):
        """Number of leaf conditions (recursive count, ignoring groups/operators)."""
        conditions = self.configuration.get("conditions") or {}
        return count_conditions_tree(conditions)


class AutomationExecution(BaseModel):
    """Activity executions for an automation (execution time, window, results)."""

    executed_at = models.DateTimeField(db_index=True)
    window_start = models.DateTimeField()
    window_end = models.DateTimeField()
    matched_cves_count = models.IntegerField(default=0)

    automation = models.ForeignKey(
        Automation, on_delete=models.CASCADE, related_name="executions"
    )
    report = models.ForeignKey(
        "changes.Report",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="automation_executions",
    )
    impact_summary = models.JSONField(null=True, blank=True, default=None)
    cves_table_data = models.JSONField(null=True, blank=True, default=None)

    class Meta:
        db_table = "opencve_automation_executions"
        ordering = ["-executed_at"]

    def __str__(self):
        return f"{self.automation.name} - {self.executed_at}"

    @property
    def slug(self):
        """URL slug from execution time (e.g. 2026-02-18-14-00)."""
        return self.executed_at.strftime("%Y-%m-%d-%H-%M")


class AutomationRunResult(BaseModel):
    """Single result from an automation execution (report, notification, PDF, etc.).
    All result-specific data (report day, file path, url, etc.) is in details (JSONB).
    """

    STATUS_SUCCESS = "success"
    STATUS_SKIPPED = "skipped"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = [
        (STATUS_SUCCESS, "Success"),
        (STATUS_SKIPPED, "Skipped"),
        (STATUS_FAILED, "Failed"),
    ]

    automation_execution = models.ForeignKey(
        AutomationExecution, on_delete=models.CASCADE, related_name="results"
    )
    output_type = models.CharField(max_length=64)
    label = models.CharField(max_length=256)
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default=STATUS_SUCCESS,
    )
    details = models.JSONField(null=True, blank=True, default=dict)  # noqa: B008

    class Meta:
        db_table = "opencve_automation_execution_results"
        ordering = ["created_at"]

    def __str__(self):
        return f"{self.label} ({self.automation_execution_id})"

    @property
    def summary_display(self):
        """Human-readable one-line summary from details (e.g. "Slack #infra (sent)", "13 CVEs assigned to \"bob@...\"")."""
        details = self.details or {}
        if self.output_type == "notification_sent":
            channel = details.get("channel")
            status = details.get("status")
            if channel:
                return f"{channel} ({status})" if status else channel
            return self.label
        if self.output_type == "report":
            cve_count = details.get("cve_count")
            if cve_count is not None:
                return f"{cve_count} CVE(s) included"
            return self.label
        if self.output_type == "pdf":
            size_mb = details.get("size_mb")
            if size_mb is not None:
                return f"Size: {size_mb} MB"
            return self.label
        if self.output_type == "ai_summary":
            preview = details.get("preview")
            if preview:
                words = preview.split()
                return " ".join(words[:15]) + ("..." if len(words) > 15 else "")
            return self.label
        if self.output_type == "assignment":
            summary = details.get("summary")
            if summary:
                return summary
            assigned_count = details.get("assigned_count")
            assignee = details.get("assignee")
            if assigned_count is not None:
                base = f"{assigned_count} CVEs assigned"
                return f'{base} to "{assignee}"' if assignee else base
            return self.label
        if self.output_type == "status_change":
            summary = details.get("summary")
            if summary:
                return summary
            from_status = details.get("from_status")
            to_status = details.get("to_status")
            updated_count = details.get("updated_count")
            if from_status and to_status and updated_count is not None:
                return (
                    f'{updated_count} CVEs moved from "{from_status}" → "{to_status}"'
                )
            if updated_count is not None:
                return f"{updated_count} CVE(s) updated"
            return self.label
        return details.get("summary") or "—"

    OUTPUT_TYPE_ICONS = {
        "notification_sent": "fa-envelope",
        "report": "fa-file-text-o",
        "assignment": "fa-users",
        "status_change": "fa-check-circle",
        "pdf": "fa-file-pdf-o",
        "ai_summary": "fa-lightbulb-o",
    }

    @property
    def detail_icon_class(self):
        """Font Awesome icon class for this result type (e.g. for the detail box title)."""
        return self.OUTPUT_TYPE_ICONS.get(self.output_type, "fa-file-o")

    @property
    def detail_action_label(self):
        """Label for the action button linking to this result's detail page."""
        if self.output_type == "notification_sent":
            return "See response"
        if self.output_type == "report":
            return "See report"
        if self.output_type == "pdf":
            return "Download PDF"
        if self.output_type == "ai_summary":
            return "See Summary"
        if self.output_type == "assignment":
            return "Assignments"
        if self.output_type == "status_change":
            return "Status changes"
        return "View"


class CveTracker(BaseModel):
    """Track CVE assignments and status within projects"""

    STATUS_CHOICES = [
        ("to_evaluate", "To evaluate"),
        ("pending_review", "Pending review"),
        ("analysis_in_progress", "Analysis in progress"),
        ("remediation_in_progress", "Remediation in progress"),
        ("evaluated", "Evaluated"),
        ("resolved", "Resolved"),
        ("not_applicable", "Not applicable"),
        ("risk_accepted", "Risk accepted"),
    ]

    status = models.CharField(
        max_length=32, choices=STATUS_CHOICES, null=True, blank=True
    )
    assigned_at = models.DateTimeField(auto_now_add=True)

    # Relationships
    cve = models.ForeignKey(
        "cves.Cve", on_delete=models.CASCADE, related_name="trackers"
    )
    project = models.ForeignKey(
        Project, on_delete=models.CASCADE, related_name="cve_trackers"
    )
    assignee = models.ForeignKey(
        "users.User",
        on_delete=models.CASCADE,
        related_name="assigned_cves",
        null=True,
        blank=True,
    )

    class Meta:
        db_table = "opencve_cve_trackers"
        constraints = [
            models.UniqueConstraint(
                fields=["cve", "project"],
                name="ix_unique_cve_project_tracker",
            )
        ]

    def __str__(self):
        return f"{self.cve.cve_id} ({self.project.name})"

    @classmethod
    def update_tracker(cls, project, cve, assignee=Ellipsis, status=Ellipsis):
        """
        Get or create a tracker, update assignee and/or status,
        and delete it if both are empty.
        """
        tracker, _ = cls.objects.get_or_create(cve=cve, project=project)

        # Update assignee if provided (None means clear, Ellipsis means skip)
        if assignee is not Ellipsis:
            tracker.assignee = assignee

        # Update status if provided (None or empty string means clear, Ellipsis means skip)
        if status is not Ellipsis:
            tracker.status = status if status else None

        # If tracker has no status and no assignee, delete it
        if not tracker.status and not tracker.assignee:
            tracker.delete()
            return None

        tracker.save()
        return tracker


class CveComment(BaseModel):
    """Comments for a CVE within a project."""

    body = models.TextField()
    edited = models.BooleanField(default=False)

    # Relationships
    parent = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="replies",
    )
    cve = models.ForeignKey(
        "cves.Cve", on_delete=models.CASCADE, related_name="project_comments"
    )
    project = models.ForeignKey(
        Project, on_delete=models.CASCADE, related_name="cve_comments"
    )
    author = models.ForeignKey(
        "users.User", on_delete=models.CASCADE, related_name="cve_comments"
    )

    class Meta:
        db_table = "opencve_cve_comments"
        ordering = ["created_at"]
