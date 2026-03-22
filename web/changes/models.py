import json
import pathlib

from django.conf import settings
from django.db import models
from django.utils import timezone

from cves.models import Cve
from opencve.models import BaseModel
from projects.models import Project


class Change(BaseModel):
    path = models.TextField(default=None)
    # This field is not useful anymore and will
    # be removed in a future version.
    commit = models.CharField(max_length=40)
    types = models.JSONField(default=list)

    # Relationships
    cve = models.ForeignKey(Cve, on_delete=models.CASCADE, related_name="changes")

    class Meta:
        db_table = "opencve_changes"
        constraints = [
            models.UniqueConstraint(
                fields=["created_at", "cve_id"],
                name="ix_unique_cve_created_at",
            )
        ]

    @property
    def full_path(self):
        return pathlib.Path(settings.KB_REPO_PATH) / self.path

    @property
    def kb_data(self):
        with open(self.full_path) as f:
            data = json.load(f)
        return data

    @property
    def change_data(self):
        kb_change = [
            c
            for c in self.kb_data["opencve"].get("changes", [])
            if c["id"] == str(self.id)
        ]

        return kb_change[0] if kb_change else {}

    def get_previous_change(self):
        return (
            Change.objects.filter(created_at__lt=self.created_at)
            .filter(cve=self.cve)
            .order_by("-created_at")
            .first()
        )


class Report(BaseModel):
    PERIOD_DAILY = "daily"
    PERIOD_WEEKLY = "weekly"
    PERIOD_CHOICES = [
        (PERIOD_DAILY, "Daily"),
        (PERIOD_WEEKLY, "Weekly"),
    ]

    seen = models.BooleanField(default=False)
    ai_summary = models.TextField(
        null=True,
        blank=True,
    )

    day = models.DateField(default=timezone.now)
    period_type = models.CharField(
        max_length=20,
        choices=PERIOD_CHOICES,
        default=PERIOD_DAILY,
    )
    period_timezone = models.CharField(max_length=64, default="UTC")
    project = models.ForeignKey(
        Project, on_delete=models.CASCADE, related_name="reports"
    )
    automation = models.ForeignKey(
        "projects.Automation",
        on_delete=models.CASCADE,
        related_name="reports",
        null=True,
        blank=True,
    )
    changes = models.ManyToManyField(Change)

    class Meta:
        db_table = "opencve_reports"
        constraints = [
            models.UniqueConstraint(
                fields=["day", "period_type", "project_id", "automation_id"],
                name="ix_unique_project_period_automation",
            ),
        ]

    @property
    def vendors_as_html(self):
        return self.details["vendors"]

    @property
    def cves_as_html(self):
        return self.details["cves"]
