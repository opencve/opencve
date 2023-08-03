import importlib

from django.core.validators import RegexValidator
from django.db import models
from django.urls import reverse

from opencve.models import BaseModel
from projects.utils import get_default_configuration
from users.models import User


def get_default_subscriptions():
    return dict(vendors=[], products=[])


class Project(BaseModel):
    name = models.CharField(max_length=256)  # TODO: add a regex constraint
    description = models.TextField(blank=True, null=True)
    subscriptions = models.JSONField(default=get_default_subscriptions)

    # Relationships
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="projects")

    class Meta:
        db_table = "opencve_projects"
        constraints = [
            models.UniqueConstraint(
                fields=["name", "user_id"], name="ix_unique_projects"
            )
        ]

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("project", kwargs={"name": self.name})

    @property
    def subscriptions_count(self):
        vendors = self.subscriptions["vendors"]
        products = self.subscriptions["products"]

        return len(vendors) + len(products)


class Notification(BaseModel):
    name = models.CharField(
        max_length=256,
        validators=[
            RegexValidator(
                regex="^[a-zA-Z0-9\-_ ]+$",
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
