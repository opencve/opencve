from flask import request

from opencve.extensions import db
from opencve.models.users import User
from opencve.models.vendors import Vendor


def test_home_cve_redirect(client):
    response = client.get("/")
    assert response.status_code == 302

    with client:
        response = client.get("/", follow_redirects=True)
        assert response.status_code == 200
        assert request.path == "/cve"


def test_home_welcome_redirect(app, client):
    app.config["DISPLAY_WELCOME"] = True
    response = client.get("/")
    assert response.status_code == 302

    with client:
        response = client.get("/", follow_redirects=True)
        assert response.status_code == 200
        assert request.path == "/welcome"
        assert b"<title>Welcome to OpenCVE</title>" in response.data
        assert b"<h1>Welcome to OpenCVE</h1>" in response.data


def test_home_terms(app, client):
    response = client.get("/terms")
    assert response.status_code == 404

    response = client.get("/register")
    assert b"Terms of Service" not in response.data

    app.config["DISPLAY_TERMS"] = True
    response = client.get("/terms")
    assert response.status_code == 200
    assert b"Terms of Service and Privacy Policy" in response.data
    response = client.get("/register")
    assert b"Terms of Service" in response.data


def test_no_activity(client, login):
    response = client.get("/")
    assert response.status_code == 200
    assert (
        b'You have to subscribe to <a href="/vendors">products and vendors</a> to see their last changes.'
        in response.data
    )


def test_subscription_without_changes(client, login):
    user = User.query.first()
    vendor = Vendor(name="opencve")
    db.session.add(vendor)
    user.vendors.append(vendor)
    db.session.commit()

    response = client.get("/")
    assert response.status_code == 200
    assert b"Your subscriptions haven't changed yet." in response.data


def test_activity_new_cve(client, login, handle_events):
    user = User.query.first()
    handle_events("modified_cves/CVE-2018-18074.json")
    user.vendors.append(Vendor.query.filter_by(name="canonical").first())
    db.session.commit()

    response = client.get("/")
    assert response.status_code == 200
    assert (
        b'<a href="/cve/CVE-2018-18074">CVE-2018-18074</a> is a new CVE'
        in response.data
    )


def test_activity_cve_changed(client, login, create_cve, handle_events):
    create_cve("CVE-2018-18074")
    user = User.query.first()
    user.vendors.append(Vendor.query.filter_by(name="canonical").first())
    db.session.commit()

    response = client.get("/")
    assert response.status_code == 200
    assert b"Your subscriptions haven't changed yet." in response.data

    handle_events("modified_cves/CVE-2018-18074_references.json")
    response = client.get("/")
    assert response.status_code == 200
    assert (
        b'<a href="/cve/CVE-2018-18074">CVE-2018-18074</a> has changed' in response.data
    )
    assert (
        b"<strong>1</strong> changed, <strong>1</strong> added, <strong>7</strong> removed"
        in response.data
    )


def test_list_paginated(app, client, login, handle_events):
    old = app.config["ACTIVITIES_PER_PAGE"]
    app.config["ACTIVITIES_PER_PAGE"] = 2

    user = User.query.first()
    for cve in ["CVE-2018-18074", "CVE-2019-17052", "CVE-2020-26116"]:
        handle_events(f"modified_cves/{cve}.json")
    user.vendors.append(Vendor.query.filter_by(name="canonical").first())
    user.vendors.append(Vendor.query.filter_by(name="linux").first())
    user.vendors.append(Vendor.query.filter_by(name="python").first())
    db.session.commit()

    # Changes are ordered using the lastModifiedDate field of each CVE
    response = client.get("/")
    assert response.status_code == 200
    assert (
        b'<a href="/cve/CVE-2019-17052">CVE-2019-17052</a> is a new CVE'
        in response.data
    )
    assert (
        b'<a href="/cve/CVE-2020-26116">CVE-2020-26116</a> is a new CVE'
        in response.data
    )

    response = client.get("/?page=2")
    assert response.status_code == 200
    assert (
        b'<a href="/cve/CVE-2018-18074">CVE-2018-18074</a> is a new CVE'
        in response.data
    )

    response = client.get("/?page=3")
    assert response.status_code == 404

    app.config["ACTIVITIES_PER_PAGE"] = old
