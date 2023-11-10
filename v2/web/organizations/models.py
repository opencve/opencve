from django.db import models
from django.utils import timezone

from opencve.models import BaseModel
from users.models import User


class Organization(BaseModel):
    name = models.CharField(max_length=100)

    # Relationships
    members = models.ManyToManyField(User, through="Membership")

    class Meta:
        db_table = "opencve_organizations"
        permissions = (
            ("add_member", "Add member"),
        )

    def __str__(self):
        return self.name


class Membership(models.Model):
    OWNER = "owner"
    MEMBER = "member"
    ROLES = [
        (OWNER, "owner"),
        (MEMBER, "member"),
    ]
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    role = models.CharField(max_length=10, choices=ROLES, default=MEMBER)
    email = models.EmailField(blank=True)
    date_invited = models.DateField(default=timezone.now)
    date_joined = models.DateField(blank=True, null=True)
    key = models.CharField(max_length=64, blank=True, null=True)

    class Meta:
        db_table = "opencve_memberships"
