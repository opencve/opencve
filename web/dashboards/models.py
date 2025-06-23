import uuid

from django.db import models

from opencve.models import BaseModel
from organizations.models import Organization
from projects.models import Project
from users.models import User


class Dashboard(BaseModel):
    organization = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name="dashboards"
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="dashboards")
    name = models.CharField(max_length=255, default="Default Dashboard")
    config = models.JSONField(default=dict)
    is_default = models.BooleanField(default=False)

    class Meta:
        db_table = "opencve_dashboards"
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "user", "name"],
                name="ix_unique_dashboard_organization_user_name",
            ),
            models.UniqueConstraint(
                fields=["organization", "user"],
                condition=models.Q(is_default=True),
                name="ix_unique_dashboard_organization_user_default",
            ),
        ]

    @staticmethod
    def get_default_config(request):
        project = Project.objects.filter(
            organization=request.current_organization, active=True
        ).first()

        if project:
            widgets = [
                {
                    "h": 7,
                    "w": 8,
                    "x": 0,
                    "y": 0,
                    "id": str(uuid.uuid4()),
                    "type": "activity",
                    "title": "CVE Activity",
                    "config": {"activities_view": "all"},
                },
                {
                    "h": 5,
                    "w": 8,
                    "x": 0,
                    "y": 7,
                    "id": str(uuid.uuid4()),
                    "type": "project_cves",
                    "title": "CVEs by Project",
                    "config": {"project_id": str(project.id), "show_project_info": 1},
                },
            ]
        else:
            widgets = [
                {
                    "h": 12,
                    "w": 8,
                    "x": 0,
                    "y": 0,
                    "id": str(uuid.uuid4()),
                    "type": "activity",
                    "title": "CVE Activity",
                    "config": {"activities_view": "all"},
                }
            ]

        widgets.extend(
            [
                {
                    "h": 3,
                    "w": 4,
                    "x": 8,
                    "y": 0,
                    "id": str(uuid.uuid4()),
                    "type": "projects",
                    "title": "Projects",
                    "config": {},
                },
                {
                    "h": 2,
                    "w": 4,
                    "x": 8,
                    "y": 3,
                    "id": str(uuid.uuid4()),
                    "type": "tags",
                    "title": "Tags",
                    "config": {},
                },
                {
                    "h": 3,
                    "w": 4,
                    "x": 8,
                    "y": 5,
                    "id": str(uuid.uuid4()),
                    "type": "views",
                    "title": "Views",
                    "config": {},
                },
                {
                    "h": 4,
                    "w": 4,
                    "x": 8,
                    "y": 8,
                    "id": str(uuid.uuid4()),
                    "type": "last_reports",
                    "title": "Recent Reports",
                    "config": {},
                },
            ]
        )
        return {"widgets": widgets}
