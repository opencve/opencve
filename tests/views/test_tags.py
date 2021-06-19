from flask import request

from opencve.extensions import db
from opencve.models.cve import Cve
from opencve.models.tags import UserTag
from opencve.models.users import User


def test_redirect_auth(client):
    response = client.get("/account/tags")
    assert response.status_code == 302

    with client:
        response = client.get("/account/tags", follow_redirects=True)
        assert response.status_code == 200
        assert request.path == "/login"


def test_no_tags(client, login):
    response = client.get("/account/tags")
    assert response.status_code == 200
    assert b"You have no tag yet." in response.data


def test_list_tags(client, login):
    user = User.query.first()

    # Create 5 tags for the user
    for i in range(5):
        tag = UserTag(
            name=f"tag{i}",
            description="my description",
            color="#fff",
            user=user,
        )
        db.session.add(tag)
    db.session.commit()

    response = client.get("/account/tags")
    assert response.status_code == 200
    assert b"tag0" in response.data
    assert b"tag1" in response.data
    assert b"tag2" in response.data
    assert b"tag3" in response.data
    assert b"tag4" in response.data


def test_create_tag(client, login):
    response = client.post(
        "/account/tags",
        data={"name": "tag1", "description": "my description", "color": "#ffffff"},
    )
    assert response.status_code == 302

    tag = UserTag.query.first()
    assert tag.name == "tag1"
    assert tag.description == "my description"
    assert tag.color == "#ffffff"

    with client:
        response = client.post(
            "/account/tags",
            data={"name": "tag2", "description": "my description", "color": "#ffffff"},
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert b"The tag tag2 has been successfully added." in response.data
        assert b"tag1" in response.data
        assert b"tag2" in response.data


def test_create_tag_invalid_form(client, login):
    response = client.post("/account/tags", data={})
    assert b"Name is required" in response.data

    response = client.post(
        "/account/tags",
        data={"name": "my tag", "color": "not_valid"},
    )
    assert b"Color must be in hexadecimal format" in response.data


def test_create_existing_tag(client, login):
    response = client.post(
        "/account/tags",
        data={"name": "tag1", "description": "my description", "color": "#ffffff"},
        follow_redirects=True,
    )
    assert b"The tag tag1 has been successfully added." in response.data

    response = client.post(
        "/account/tags",
        data={"name": "tag1", "description": "my description", "color": "#ffffff"},
        follow_redirects=True,
    )
    assert b"This tag already exists." in response.data


def test_update_tag(client, login):
    response = client.post(
        "/account/tags",
        data={
            "name": "tag1",
            "description": "my original description",
            "color": "#ffffff",
        },
        follow_redirects=True,
    )
    assert b"my original description" in response.data

    response = client.post(
        "/account/tags/tag1",
        data={"description": "my edited description", "color": "#000000"},
        follow_redirects=True,
    )
    assert not b"my original description" in response.data
    assert b"my edited description" in response.data

    tag = UserTag.query.first()
    assert tag.name == "tag1"
    assert tag.description == "my edited description"
    assert tag.color == "#000000"


def test_delete_tag(client, login):
    response = client.get("/account/tags/tag1/delete")
    assert response.status_code == 404

    client.post(
        "/account/tags",
        data={
            "name": "tag1",
            "description": "my original description",
            "color": "#ffffff",
        },
    )

    response = client.get("/account/tags/tag1/delete")
    assert response.status_code == 200
    assert (
        b"Do you really want to delete the <strong>tag1</strong> tag ?" in response.data
    )

    response = client.post("/account/tags/tag1/delete", follow_redirects=True)
    assert b"The tag tag1 has been deleted." in response.data
    assert UserTag.query.count() == 0


def test_associate_tags(client, login, create_cve, create_tag):
    create_cve("CVE-2018-18074")
    create_tag("tag1", "my description", "#ffffff")
    create_tag("tag2", "my description", "#ffffff")

    with client:
        # The CVE has no tag
        response = client.get("/cve/CVE-2018-18074")
        assert not b">tag1</span>" in response.data
        assert not b">tag2</span>" in response.data
        cve = Cve.query.filter_by(cve_id="CVE-2018-18074").first()
        assert not cve.tags

        # CVE not found
        response = client.post("/cve/CVE-2000-0001/tags", data={})
        assert response.status_code == 404

        # Tag not found
        response = client.post("/cve/CVE-2018-18074/tags", data={"tags": ["notfound"]})
        assert response.status_code == 404

        # Associate tags
        response = client.post(
            "/cve/CVE-2018-18074/tags",
            data={"tags": ["tag1", "tag2"]},
            follow_redirects=True,
        )
        assert b"The CVE tags have been updated." in response.data
        assert b">tag1</span>" in response.data
        assert b">tag2</span>" in response.data
        cve = Cve.query.filter_by(cve_id="CVE-2018-18074").first()
        assert len(cve.tags) == 2
        assert [t.name for t in cve.tags] == ["tag1", "tag2"]

        # Remove one tag
        response = client.post(
            "/cve/CVE-2018-18074/tags", data={"tags": ["tag1"]}, follow_redirects=True
        )
        assert b"The CVE tags have been updated." in response.data
        assert b">tag1</span>" in response.data
        assert not b">tag2</span>" in response.data
        cve = Cve.query.filter_by(cve_id="CVE-2018-18074").first()
        assert len(cve.tags) == 1
        assert cve.tags[0].name == "tag1"

        # Remove all tags
        response = client.post(
            "/cve/CVE-2018-18074/tags", data={}, follow_redirects=True
        )
        assert b"The CVE tags have been updated." in response.data
        assert not b">tag1</span>" in response.data
        assert not b">tag2</span>" in response.data
        cve = Cve.query.filter_by(cve_id="CVE-2018-18074").first()
        assert len(cve.tags) == 0
