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


def test_include_analytics(app, client):
    content = b'<script src="https://analytics.example.com/script.js"></script>'

    response = client.get("/cve")
    assert content not in response.data
    response = client.get("/login")
    assert content not in response.data

    app.config["INCLUDE_ANALYTICS"] = True
    response = client.get("/cve")
    assert content in response.data
    response = client.get("/login")
    assert content in response.data

    app.config["INCLUDE_ANALYTICS"] = False


def test_no_activity(client, login):
    response = client.get("/")
    assert response.status_code == 200
    assert b"No changes available." in response.data

    user = User.query.first()
    user.settings = {"activities_view": "subscriptions"}
    db.session.commit()

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
    assert b"No changes available." in response.data


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
    assert b"No changes available." in response.data

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


def test_list_paginated(app, client, login, handle_events, make_soup):
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

    # Page 1
    soup = make_soup(response.data)
    dates = [s.find("span").text for s in soup.find_all(attrs={"class": "time-label"})]
    assert "01 Jan 2024" in dates[0]
    assert "07 Nov 2023" in dates[1]
    dates = [
        s.find("a").text for s in soup.find_all(attrs={"class": "timeline-header"})
    ]
    assert "CVE-2019-17052" in dates[0]
    assert "CVE-2020-26116" in dates[1]

    # Page 2
    response = client.get("/?page=2")
    soup = make_soup(response.data)
    dates = [s.find("span").text for s in soup.find_all(attrs={"class": "time-label"})]
    assert "25 Jul 2022" in dates[0]
    dates = [
        s.find("a").text for s in soup.find_all(attrs={"class": "timeline-header"})
    ]
    assert "CVE-2018-18074" in dates[0]

    # Other pages
    response = client.get("/?page=3")
    assert response.status_code == 200
    assert b"No changes available." in response.data
    response = client.get("/?page=300")
    assert response.status_code == 200
    assert b"No changes available." in response.data

    app.config["ACTIVITIES_PER_PAGE"] = old


def test_list_all_or_subscriptions_activities(client, login, create_cve, handle_events):
    create_cve("CVE-2018-18074")
    handle_events("modified_cves/CVE-2018-18074_references.json")
    create_cve("CVE-2020-35188")
    handle_events("modified_cves/CVE-2020-35188_cpes.json")

    user = User.query.first()
    user.vendors.append(Vendor.query.filter_by(name="canonical").first())
    db.session.commit()

    # By default activities_view is 'all'
    response = client.get("/")
    assert response.status_code == 200
    assert b"CVE-2018-18074" in response.data
    assert b"CVE-2020-35188" in response.data

    user.settings = {"activities_view": "subscriptions"}
    db.session.commit()

    # With the 'subscriptions' view the user doesn't see all the changes
    response = client.get("/")
    assert response.status_code == 200
    assert b"CVE-2018-18074" in response.data
    assert b"CVE-2020-35188" not in response.data
