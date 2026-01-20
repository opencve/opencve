import secrets
import string

from django.contrib.auth.hashers import check_password, make_password
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

    def get_members(self, active=True):
        """Return members of the organization."""
        queryset = User.objects.filter(
            membership__organization=self,
        )

        if active:
            queryset = queryset.filter(membership__date_joined__isnull=False)

        return queryset.distinct().order_by("username")

    def __str__(self):
        return self.name


class Membership(models.Model):
    OWNER = "owner"
    MEMBER = "member"
    ROLES = [
        (OWNER, "owner"),
        (MEMBER, "member"),
    ]
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    email = models.EmailField(null=True, blank=True)
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


class OrganizationAPIToken(BaseModel):
    TOKEN_ID_LENGTH = 12
    SECRET_LENGTH = 32
    TOKEN_PREFIX = "opc_org"

    token_id = models.CharField(max_length=12, unique=True, db_index=True)
    token_hash = models.CharField(max_length=128)
    organization = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name="api_tokens"
    )
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=255, blank=True, null=True)
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_api_tokens",
    )
    last_used_at = models.DateTimeField(null=True, blank=True, db_index=True)
    is_active = models.BooleanField(default=True, db_index=True)
    revoked_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="revoked_api_tokens",
    )
    revoked_at = models.DateTimeField(null=True, blank=True, db_index=True)

    class Meta:
        db_table = "opencve_organization_api_tokens"
        ordering = ["-created_at"]

    @classmethod
    def generate_token_id(cls):
        """Generate a unique token_id."""
        chars = string.ascii_letters + string.digits
        while True:
            token_id = "".join(
                secrets.choice(chars) for _ in range(cls.TOKEN_ID_LENGTH)
            )
            if not cls.objects.filter(token_id=token_id).exists():
                return token_id

    @classmethod
    def generate_secret(cls):
        """Generate a random secret."""
        chars = string.ascii_letters + string.digits
        return "".join(secrets.choice(chars) for _ in range(cls.SECRET_LENGTH))

    @classmethod
    def create_token(cls, organization, name, description, created_by):
        """Create a new token and return the full token string."""
        token_id = cls.generate_token_id()
        secret = cls.generate_secret()
        token_hash = make_password(secret)

        token = cls.objects.create(
            token_id=token_id,
            token_hash=token_hash,
            organization=organization,
            name=name,
            description=description,
            created_by=created_by,
        )

        return f"{cls.TOKEN_PREFIX}.{token_id}.{secret}"

    def verify_token(self, secret):
        """Verify if the provided secret matches the stored hash."""
        if not self.is_active:
            return False
        return check_password(secret, self.token_hash)

    def revoke(self, revoked_by=None):
        """Revoke the token by setting is_active to False and recording who revoked it."""
        self.is_active = False
        if revoked_by:
            self.revoked_by = revoked_by
        self.revoked_at = timezone.now()
        self.save(update_fields=["is_active", "revoked_by", "revoked_at", "updated_at"])

    def update_last_used(self):
        """Update the last_used_at timestamp."""
        self.last_used_at = timezone.now()
        self.save(update_fields=["last_used_at", "updated_at"])

    def __str__(self):
        return f"{self.name} ({self.organization.name})"
