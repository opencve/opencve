import json
import uuid
from pathlib import Path

import pytest
from django.db import connection
from django.utils.timezone import now
from psycopg2.extras import Json

from cves.models import Cve
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
def auth_client(db, client, create_user):
    def _auth_client(user=None):
        if user is None:
            user = create_user()
        client.login(username=user.username, password=TEST_PASSWORD)
        return client

    return _auth_client


@pytest.fixture
def create_organization(create_user):
    def _create_organization(name, user=None, owner=True):
        organization = Organization.objects.create(name=name)

        if user:
            Membership.objects.create(
                user=user,
                organization=organization,
                role=Membership.OWNER if owner else Membership.MEMBER,
                date_invited=now(),
                date_joined=now(),
            )
        return organization

    return _create_organization


@pytest.fixture(scope="function")
def open_file():
    def _open_file(name):
        with open(Path(__file__).parent.resolve() / "data" / name) as f:
            return json.load(f)

    return _open_file


@pytest.fixture(scope="function")
def open_raw_file():
    def _open_raw_file(name):
        with open(Path(__file__).parent.resolve() / "data" / name) as f:
            return f.read()

    return _open_raw_file


@pytest.fixture(scope="function")
def create_cve(open_file):
    def _create_cve(cve_id):
        year = cve_id.split("-")[1]
        cve_data = open_file(f"kb/{year}/{cve_id}.json")

        parameters = [
            cve_data["cve"],
            cve_data["opencve"]["created"]["data"],
            cve_data["opencve"]["updated"]["data"],
            cve_data["opencve"]["description"]["data"],
            cve_data["opencve"]["title"]["data"],
            Json(cve_data["opencve"]["metrics"]),
            Json(cve_data["opencve"]["vendors"]["data"]),
            Json(cve_data["opencve"]["weaknesses"]["data"]),
            Json([]),
        ]

        with connection.cursor() as cursor:
            cursor.execute(
                "CALL cve_upsert(%s, %s, %s, %s, %s, %s, %s, %s, %s);", parameters
            )
            return Cve.objects.get(cve_id=cve_id)

    return _create_cve


@pytest.fixture(scope="function")
def create_cves(create_cve):
    def _create_cves(cves):
        return [create_cve(cve) for cve in cves]

    return _create_cves
