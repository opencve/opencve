import datetime
import json
import os
from pathlib import Path
from unittest.mock import patch, Mock

tests_directory = os.path.dirname(os.path.realpath(__file__))
os.environ["OPENCVE_CONFIG"] = str(Path(tests_directory) / "opencve.cfg")
os.environ["OPENCVE_WELCOME_FILES"] = str(
    Path(tests_directory).parent / "opencve/templates/_welcome"
)

import pytest
from bs4 import BeautifulSoup
from flask import url_for

from opencve import create_app
from opencve.commands.utils import CveUtil
from opencve.extensions import db
from opencve.models.cve import Cve
from opencve.models.users import User
from opencve.models.vendors import Vendor
from opencve.models.products import Product
from opencve.tasks.events import handle_events as handle_events_task


@pytest.fixture(scope="session", autouse=True)
def app():
    _app = create_app("test")
    ctx = _app.app_context()
    ctx.push()

    # create the tables
    db.create_all()

    yield _app

    # drop the tables
    db.session.close()
    db.drop_all()


@pytest.fixture(scope="function", autouse=True)
def truncate_db_tables(app):
    # Truncate all tables
    meta = db.metadata
    for table in reversed(meta.sorted_tables):
        db.session.execute(table.delete())
    db.session.commit()


@pytest.fixture(scope="function")
def client(app):
    _client = app.test_client()
    yield _client


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
def create_cve(app, open_file):
    def _create_cve(cve_id):
        CveUtil.create_cve(open_file(f"cves/{cve_id}.json"))
        return Cve.query.filter_by(cve_id=cve_id).first()

    return _create_cve


@pytest.fixture
def handle_events(app, open_file):
    def _handle_events(name):
        def _has_changed():
            current = Mock()
            current.value = Mock()
            current.value.return_value = "currentsha256"
            return current, "newsha256"

        def _download_modified():
            return open_file(name)

        with patch("opencve.tasks.events.has_changed") as mock:
            mock.return_value = _has_changed()

            with patch("opencve.tasks.events.download_modified_items") as mock:
                mock.return_value = _download_modified()
                handle_events_task()

    return _handle_events


@pytest.fixture
def create_user(app):
    def _create_user(name="user"):
        user = User(
            username=name,
            email=f"{name}@opencve.io",
            active=True,
            admin=False,
            email_confirmed_at=datetime.datetime.utcnow(),
            password=app.user_manager.hash_password("password"),
        )
        db.session.add(user)
        db.session.commit()
        return user

    return _create_user


@pytest.fixture
def create_vendor():
    def _create_vendor(vendor_name, product_name=None):
        vendor = Vendor(name=vendor_name)
        if product_name:
            vendor.products.append(Product(name=product_name))
        db.session.add(vendor)
        db.session.commit()
        return vendor

    return _create_vendor


@pytest.fixture
def make_soup():
    def _make_soup(data):
        return BeautifulSoup(data, "html.parser")

    return _make_soup


@pytest.fixture
def get_cve_names():
    def _get_cve_names(soup):
        return [
            cve.text
            for cve in soup.select("table#cves tr.cve-header td:first-child strong")
        ]

    return _get_cve_names


@pytest.fixture(scope="function")
def login(create_user, client):
    create_user()
    client.post(
        url_for("user.login"),
        data={"username": "user", "password": "password"},
        follow_redirects=True,
    )

    yield

    client.post(url_for("user.logout"), follow_redirects=True)
