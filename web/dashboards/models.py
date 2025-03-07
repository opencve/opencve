from django.db import models

from opencve.models import BaseModel
from users.models import User


class DashboardConfig(BaseModel):
    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name="dashboard_config"
    )
    config = models.JSONField(default=dict)

    class Meta:
        db_table = "opencve_dashboard_configs"
