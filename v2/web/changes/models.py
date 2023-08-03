import hashlib
import uuid

from django.db import models

from cves.models import Cve
from opencve.models import BaseModel
from projects.models import Project


def get_random_sha256():
    return hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()


class Task(BaseModel):
    # TODO: remove this model as it's no longer used
    nvd_checksum = models.CharField(
        max_length=64, unique=True, default=get_random_sha256
    )

    class Meta:
        db_table = "opencve_tasks"

    def __str__(self):
        return self.nvd_checksum


class Change(BaseModel):
    path = models.TextField(default=None)
    commit = models.CharField(max_length=40)

    # Relationships
    cve = models.ForeignKey(Cve, on_delete=models.CASCADE, related_name="changes")

    class Meta:
        db_table = "opencve_changes"


class Event(BaseModel):
    class EventType(models.TextChoices):
        NEW_CVE = "new_cve", "New CVE"
        FIRST_TIME = "first_time", "Vendor(s)/Product(s) appeared for the first time"
        REFERENCES = "references", "Reference(s) changed"
        CPES = "cpes", "CPE(s) changed"
        CVSS = "cvss", "CVSS changed"
        SUMMARY = "summary", "Summary changed"
        CWES = "cwes", "CWE(s) changed"

    type = models.CharField(
        max_length=10,
        choices=EventType.choices,
        default=EventType.NEW_CVE,
    )
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
    details = models.JSONField()

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
