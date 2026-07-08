from django.core.exceptions import ValidationError

from projects.models import Project

RESERVED_PROJECT_NAMES = frozenset({"add"})
PROJECT_NAME_RESERVED_MESSAGE = "This project is reserved."
PROJECT_NAME_TAKEN_MESSAGE = "This project already exists."


def validate_project_name(name, *, organization=None, exclude_project=None):
    """Validate the project name"""
    if name in RESERVED_PROJECT_NAMES:
        raise ValidationError(PROJECT_NAME_RESERVED_MESSAGE)

    if organization is None:
        return

    queryset = Project.objects.filter(name=name, organization=organization)
    if exclude_project is not None:
        queryset = queryset.exclude(pk=exclude_project.pk)

    if queryset.exists():
        raise ValidationError(PROJECT_NAME_TAKEN_MESSAGE)
