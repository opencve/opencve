from django.db import IntegrityError

from organizations.utils import is_organization_name_unique_violation


def test_is_organization_name_unique_violation_true():
    exc = IntegrityError(
        'duplicate key value violates unique constraint "ix_unique_organization_name"'
    )
    assert is_organization_name_unique_violation(exc) is True


def test_is_organization_name_unique_violation_false():
    exc = IntegrityError(
        'duplicate key value violates unique constraint "ix_unique_organization_project_name"'
    )
    assert is_organization_name_unique_violation(exc) is False
