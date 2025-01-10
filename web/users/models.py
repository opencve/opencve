from django.contrib.auth.models import AbstractUser
from django.contrib.postgres.indexes import GinIndex
from django.core.validators import RegexValidator
from django.db import models
from django.urls import reverse

from cves.models import Cve
from opencve.models import BaseModel


def get_default_settings():
    return {"activities_view": "all"}


class User(BaseModel, AbstractUser):
    settings = models.JSONField(default=get_default_settings)

    class Meta:
        db_table = "opencve_users"

    def __str__(self):
        return self.username

    def list_organizations(self):
        from organizations.models import Membership

        memberships = (
            Membership.objects.filter(
                user=self,
                role__in=[Membership.OWNER, Membership.MEMBER],
                date_joined__isnull=False,
            )
            .order_by("organization__name")
            .all()
        )
        return [m.organization for m in memberships]

    def get_setting(self, key, default=None):
        return self.settings.get(key, default)

    def update_setting(self, key, value):
        self.settings[key] = value
        self.save(update_fields=["settings"])


class UserTag(BaseModel):
    name = models.CharField(
        max_length=64,
        validators=[
            RegexValidator(
                regex="^[a-zA-Z0-9\-_]+$",
                message="Only alphanumeric, dash and underscore characters are accepted",
            ),
        ],
    )
    color = models.CharField(
        max_length=7,
        validators=[
            RegexValidator(
                regex="^#[0-9a-fA-F]{6}$",
                message="Color must be in hexadecimal format",
            ),
        ],
        default="#000000",
    )
    description = models.CharField(max_length=512, null=True, blank=True)

    # Relationships
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="tags")

    class Meta:
        db_table = "opencve_users_tags"
        constraints = [
            models.UniqueConstraint(
                fields=["name", "user_id"], name="ix_unique_name_userid"
            )
        ]

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return f"{reverse('cves')}?tag={self.name}"


class CveTag(BaseModel):
    tags = models.JSONField()

    # Relationships
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="cve_tags")
    cve = models.ForeignKey(Cve, on_delete=models.CASCADE, related_name="cve_tags")

    class Meta:
        db_table = "opencve_cves_tags"
        indexes = [
            GinIndex(name="ix_cves_tags", fields=["tags"]),
        ]
