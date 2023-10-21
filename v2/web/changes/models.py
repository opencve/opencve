from django.db import models

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


class Event(BaseModel):
    type = models.CharField(max_length=50)
    details = models.JSONField()

    # Relationships
    cve = models.ForeignKey(Cve, on_delete=models.CASCADE, related_name="events")
    change = models.ForeignKey(Change, on_delete=models.CASCADE, related_name="events")

    class Meta:
        db_table = "opencve_events"

    def __str__(self):
        return self.type


class Report(BaseModel):
    seen = models.BooleanField(default=False)

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="reports")
    changes = models.ManyToManyField(Change)

    class Meta:
        db_table = "opencve_reports"
        constraints = [
            models.UniqueConstraint(
                fields=["created_at", "project_id"], name="ix_unique_project_created_at"
            )
        ]

    @property
    def vendors_as_html(self):
        return self.details["vendors"]

    @property
    def cves_as_html(self):
        return self.details["cves"]
