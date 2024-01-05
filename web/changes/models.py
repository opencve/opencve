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
    commit = models.CharField(max_length=40)
    types = models.JSONField(default=list)

    # Relationships
    cve = models.ForeignKey(Cve, on_delete=models.CASCADE, related_name="changes")

    class Meta:
        db_table = "opencve_changes"
        constraints = [
            models.UniqueConstraint(
                fields=["created_at", "cve_id", "commit"], name="ix_unique_cve_commit_created_at"
            )
        ]

    @property
    def full_path(self):
        return pathlib.Path(settings.KB_REPO_PATH) / self.path

    @property
    def events(self):
        with open(self.full_path) as f:
            change_data = json.load(f)
        return change_data.get("events", {})

    @property
    def kb_data(self):
        with open(self.full_path) as f:
            data = json.load(f)
        return data

    def get_previous_change(self):
        return (
            Change.objects.filter(created_at__lt=self.created_at)
            .filter(cve=self.cve)
            .order_by("-created_at")
            .first()
        )


class Report(BaseModel):
    seen = models.BooleanField(default=False)

    day = models.DateField(default=timezone.now)
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="reports")
    changes = models.ManyToManyField(Change)

    class Meta:
        db_table = "opencve_reports"
        constraints = [
            models.UniqueConstraint(
                fields=["day", "project_id"], name="ix_unique_project_day"
            ),
        ]

    @property
    def vendors_as_html(self):
        return self.details["vendors"]

    @property
    def cves_as_html(self):
        return self.details["cves"]
