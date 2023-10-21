from django.db import models
from django.utils import timezone

from cves.models import Cve
from opencve.models import BaseModel
from projects.models import Project


class Change(BaseModel):
    path = models.TextField(default=None)
    commit = models.CharField(max_length=40)

    # Relationships
    cve = models.ForeignKey(Cve, on_delete=models.CASCADE, related_name="changes")

    class Meta:
        db_table = "opencve_changes"
        constraints = [
            models.UniqueConstraint(
                fields=["created_at", "cve_id", "commit"], name="ix_unique_cve_commit_created_at"
            )
        ]


class Event(BaseModel):
    type = models.CharField(max_length=50)
    details = models.JSONField()

    # Relationships
    cve = models.ForeignKey(Cve, on_delete=models.CASCADE, related_name="events")
    change = models.ForeignKey(Change, on_delete=models.CASCADE, related_name="events")

    class Meta:
        db_table = "opencve_events"
        constraints = [
            models.UniqueConstraint(
                fields=["created_at", "change_id", "type"], name="ix_unique_change_type_created_at"
            )
        ]

    def __str__(self):
        return self.type


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
