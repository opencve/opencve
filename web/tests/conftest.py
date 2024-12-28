import json
import os
import uuid
from pathlib import Path

import pytest
from django.db import connection
from django.utils.timezone import now
from psycopg2.extras import Json

from cves.models import Cve, Variable
from organizations.models import Membership, Organization
from projects.models import Notification, Project


TESTS_DIR = os.path.dirname(os.path.realpath(__file__))
TEST_PASSWORD = "password"


@pytest.fixture(autouse=True)
def configure_kb_path(settings):
    settings.KB_REPO_PATH = str(Path(TESTS_DIR) / "data/kb")


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


@pytest.fixture
def create_project():
    def _create_project(
        name, organization, description=None, active=True, vendors=None, products=None
    ):
        subscriptions = {
            "vendors": vendors if vendors else [],
            "products": products if products else [],
        }
        return Project.objects.create(
            name=name,
            organization=organization,
            description=description,
            active=active,
            subscriptions=subscriptions,
        )

    return _create_project


@pytest.fixture
def create_notification():
    def _create_notification(
        name, project, type="email", configuration=None, is_enabled=True
    ):
        return Notification.objects.create(
            name=name,
            project=project,
            type=type,
            configuration=configuration if configuration else {},
            is_enabled=is_enabled,
        )

    return _create_notification


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
        path = f"{year}/{cve_id}.json"
        cve_data = open_file(f"kb/{path}")

        parameters = [
            cve_data["cve"],
            cve_data["opencve"]["created"]["data"],
            cve_data["opencve"]["updated"]["data"],
            cve_data["opencve"]["description"]["data"],
            cve_data["opencve"]["title"]["data"],
            Json(cve_data["opencve"]["metrics"]),
            Json(cve_data["opencve"]["vendors"]["data"]),
            Json(cve_data["opencve"]["weaknesses"]["data"]),
        ]

        changes = []
        for change in cve_data["opencve"]["changes"]:
            changes.append(
                {
                    "change": change["id"],
                    "created": change["created"],
                    "updated": change["created"],
                    "file_path": path,
                    "commit_hash": "a" * 40,
                    "event_types": [e["type"] for e in change["data"]],
                }
            )
        parameters.append(Json(changes))

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


@pytest.fixture(scope="function")
def create_variable(db):
    def _create_variable(name, value):
        return Variable.objects.create(name=name, value=value)

    return _create_variable
