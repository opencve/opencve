import pytest
from werkzeug.exceptions import NotFound

from opencve.controllers.tags import UserTagController
from opencve.extensions import db
from opencve.models.tags import UserTag


def test_metas(app):
    with app.test_request_context():
        _, metas, _ = UserTagController.list()
    assert metas == {}


def test_list(app, create_user):
    user1 = create_user("user1")
    user1.tags.append(
        UserTag(
            name="mytag",
            description="my description",
            color="#fff",
            user=user1,
        )
    )
    db.session.commit()

    # User1 has one tag
    with app.test_request_context():
        tags = UserTagController.list_items({"user_id": user1.id})

    assert len(tags) == 1
    assert tags[0].user.id == user1.id
    assert tags[0].name == "mytag"
    assert tags[0].description == "my description"
    assert tags[0].color == "#fff"

    # User2 has no tag
    user2 = create_user("user2")
    with app.test_request_context():
        tags = UserTagController.list_items({"user_id": user2.id})

    assert len(tags) == 0


def test_list_paginated(app, create_user):
    user = create_user()

    # Change the pagination to 3 items
    old = app.config["TAGS_PER_PAGE"]
    app.config["TAGS_PER_PAGE"] = 3

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

    with app.test_request_context():
        tags = UserTagController.list_items({"user_id": user.id})
        assert len(tags) == 3
        assert [t.name for t in tags] == ["tag0", "tag1", "tag2"]

        tags = UserTagController.list_items({"user_id": user.id, "page": 2})
        assert len(tags) == 2
        assert [t.name for t in tags] == ["tag3", "tag4"]

        with pytest.raises(NotFound):
            UserTagController.list_items({"user_id": user.id, "page": 3})

    app.config["TAGS_PER_PAGE"] = old


def test_get(app, create_user):
    user = create_user()
    user.tags.append(
        UserTag(
            name="mytag",
            description="my description",
            color="#fff",
            user=user,
        )
    )
    db.session.commit()

    with app.test_request_context():
        tag = UserTagController.get({"user_id": user.id, "name": "mytag"})
        assert tag.name == "mytag"
        assert tag.user.id == user.id

        with pytest.raises(NotFound):
            UserTagController.get({"user_id": user.id, "name": "notfound"})
