import uuid

import pytest
from django.utils.timezone import now

from organizations.models import Membership, Organization


TEST_PASSWORD = "password"


@pytest.fixture
def create_user(db, django_user_model):
    def _create_user(**kwargs):
        kwargs["password"] = TEST_PASSWORD
        if "username" not in kwargs:
            kwargs["username"] = str(uuid.uuid4())
        return django_user_model.objects.create_user(**kwargs)

    return _create_user


@pytest.fixture
def user_client(db, client, create_user):
    def _user_client(user=None):
        if user is None:
            user = create_user()
        client.login(username=user.username, password=TEST_PASSWORD)
        return user, client

    return _user_client


@pytest.fixture
def create_organization(db, client, create_user):
    def _create_organization(name=None, user=None, owner=True):
        if user is None:
            user = create_user()
        client.login(username=user.username, password=TEST_PASSWORD)

        organization = Organization.objects.create(name=name if name else "Test Org")
        Membership.objects.create(
            user=user,
            organization=organization,
            role=Membership.OWNER if owner else Membership.MEMBER,
            date_invited=now(),
            date_joined=now(),
        )
        return user, organization

    return _create_organization
