from django.core.exceptions import ValidationError

from opencve.validators import slug_regex_validator
from organizations.models import Organization

RESERVED_ORGANIZATION_NAMES = frozenset({"add"})
ORGANIZATION_NAME_RESERVED_MESSAGE = "This organization is reserved."
ORGANIZATION_NAME_TAKEN_MESSAGE = "This organization name is not available."


def validate_organization_name(name, *, exclude_organization=None):
    """Validate the organization name"""
    slug_regex_validator(name)

    # Check if the organization name is reserved
    if name in RESERVED_ORGANIZATION_NAMES:
        raise ValidationError(ORGANIZATION_NAME_RESERVED_MESSAGE)

    # Check if the organization name is already taken
    queryset = Organization.objects.filter(name=name)
    if exclude_organization is not None:
        queryset = queryset.exclude(pk=exclude_organization.pk)

    # Check if the organization name is already taken
    if queryset.exists():
        raise ValidationError(ORGANIZATION_NAME_TAKEN_MESSAGE)
