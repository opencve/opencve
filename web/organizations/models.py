from django.db import models
from django.utils import timezone

from opencve.models import BaseModel
from opencve.validators import slug_regex_validator
from users.models import User


class Organization(BaseModel):
    name = models.CharField(
        max_length=100,
        validators=[slug_regex_validator],
    )

    # Relationships
    members = models.ManyToManyField(User, through="Membership")

    class Meta:
        db_table = "opencve_organizations"
        permissions = (("add_member", "Add member"),)

    def get_projects_vendors(self):
        projects_vendors = self.projects.values_list("subscriptions", flat=True)
        unique_vendors = set()

        for project_vendors in projects_vendors:
            unique_vendors.update(project_vendors["vendors"])
            unique_vendors.update(project_vendors["products"])

        return list(sorted(unique_vendors))

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
    role = models.CharField(max_length=20, choices=ROLES, default=MEMBER)
    date_invited = models.DateTimeField(default=timezone.now, db_index=True)
    date_joined = models.DateTimeField(null=True, blank=True, db_index=True)
    key = models.CharField(max_length=64, blank=True, null=True)

    class Meta:
        db_table = "opencve_memberships"

    @property
    def is_owner(self):
        return self.role == Membership.OWNER

    @property
    def is_invited(self):
        return not self.date_joined
