from django.db import models
from django.db.models import Q, UniqueConstraint

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
        constraints = [
            UniqueConstraint(
                fields=["name", "organization"],
                condition=Q(privacy="public"),
                name="unique_public_view_name_per_org",
            ),
            UniqueConstraint(
                fields=["name", "organization", "user"],
                condition=Q(privacy="private"),
                name="unique_private_view_name_per_user_org",
            ),
        ]

    def __str__(self):
        return self.name
