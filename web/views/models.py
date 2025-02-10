from django.db import models

from opencve.models import BaseModel
from organizations.models import Organization
from users.models import User


class View(BaseModel):
    PRIVACY_CHOICES = (
        ("private", "Private"),
        ("public", "Public"),
    )

    name = models.CharField(
        max_length=100,
    )
    query = models.TextField()
    privacy = models.CharField(max_length=7, choices=PRIVACY_CHOICES, default="private")

    # Relationship
    organization = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name="views"
    )
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="views", null=True, blank=True
    )

    class Meta:
        db_table = "opencve_views"
        unique_together = ("name", "organization")

    def __str__(self):
        return self.name
