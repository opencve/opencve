from datetime import date

import pytest
from django.core.exceptions import ValidationError
from django.utils.timezone import now
from freezegun import freeze_time

from organizations.models import Membership, Organization


def test_organization_model(create_user, create_organization):
    user = create_user(username="user1")
    org = create_organization(name="organization1", user=user)

    assert org.name == "organization1"
    assert org.members.count() == 1
    assert org.members.first() == user
    assert org.membership_set.first().role == Membership.OWNER


def test_organization_get_projects_vendors(
    create_user, create_organization, create_project
):
    user = create_user()
    organization = create_organization("myorga", user)
    create_project(name="project1", organization=organization, vendors=["foo", "bar"])
    create_project(name="project2", organization=organization, vendors=["bar", "baz"])

    assert organization.get_projects_vendors() == ["bar", "baz", "foo"]


def test_organization_name_validator(create_organization):
    orga = Organization.objects.create(name="with'quote")
    with pytest.raises(ValidationError):
        assert orga.full_clean()


def test_membership_model(create_user):
    organization = Organization.objects.create(name="orga1")

    # Owner
    owner = create_user(username="user1")
    with freeze_time("2024-01-01"):
        membership = Membership.objects.create(
            user=owner,
            organization=organization,
            role=Membership.OWNER,
            date_invited=now(),
            date_joined=now(),
        )

    assert membership.user == owner
    assert membership.organization == organization
    assert membership.role == Membership.OWNER
    assert membership.date_invited.date() == date(2024, 1, 1)
    assert membership.date_joined.date() == date(2024, 1, 1)
    assert membership.key is None
    assert membership.is_owner is True
    assert membership.is_invited is False

    # Member
    member = create_user(username="user2")
    with freeze_time("2024-01-01"):
        membership = Membership.objects.create(
            user=member,
            organization=organization,
            role=Membership.MEMBER,
            date_invited=now(),
            key="foobar",
        )

    assert membership.user == member
    assert membership.organization == organization
    assert membership.role == Membership.MEMBER
    assert membership.date_invited.date() == date(2024, 1, 1)
    assert membership.date_joined is None
    assert membership.key == "foobar"
    assert membership.is_owner is False
    assert membership.is_invited is True
