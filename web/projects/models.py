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
    return {"cvss": 0, "events": []}


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
        return self.name

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
        return f"{self.cve.cve_id} - {self.project.name}"

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
