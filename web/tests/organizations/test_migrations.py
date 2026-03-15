import importlib.util
import os

import pytest
from django.apps import apps

from organizations.models import Membership, Organization
from users.models import User


def _load_migration_function():
    """Load normalize_email_and_link_users from migration 0008 (module name is invalid Python)."""
    from organizations import migrations as org_migrations

    org_migrations_dir = os.path.dirname(org_migrations.__file__)
    path = os.path.join(
        org_migrations_dir, "0008_normalize_membership_email_and_link_users.py"
    )
    spec = importlib.util.spec_from_file_location("migration_0008", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.normalize_email_and_link_users


@pytest.mark.django_db
def test_normalizes_uppercase_email_and_links_existing_user():
    """When a membership has uppercase email and a user exists with lowercase email, link them."""
    normalize_email_and_link_users = _load_migration_function()

    user = User.objects.create_user(
        username="johndoe",
        email="john@example.com",
        password="test",
    )
    org = Organization.objects.create(name="testorg")
    membership = Membership.objects.create(
        organization=org,
        email="John@Example.com",
        role=Membership.MEMBER,
        key="invite-key",
    )

    normalize_email_and_link_users(apps, None)

    membership.refresh_from_db()
    assert membership.user_id == user.id
    assert membership.email is None


@pytest.mark.django_db
def test_normalizes_uppercase_email_when_no_matching_user():
    """When a membership has uppercase email but no user exists, only normalize the email."""
    normalize_email_and_link_users = _load_migration_function()

    org = Organization.objects.create(name="testorg")
    membership = Membership.objects.create(
        organization=org,
        email="  Foo@Bar.COM  ",
        role=Membership.MEMBER,
        key="invite-key",
    )

    normalize_email_and_link_users(apps, None)

    membership.refresh_from_db()
    assert membership.user_id is None
    assert membership.email == "foo@bar.com"


@pytest.mark.django_db
def test_does_not_change_lowercase_email():
    """Memberships that already have lowercase email are left unchanged."""
    normalize_email_and_link_users = _load_migration_function()

    org = Organization.objects.create(name="testorg")
    membership = Membership.objects.create(
        organization=org,
        email="already@lowercase.com",
        role=Membership.MEMBER,
        key="invite-key",
    )

    normalize_email_and_link_users(apps, None)

    membership.refresh_from_db()
    assert membership.user_id is None
    assert membership.email == "already@lowercase.com"
