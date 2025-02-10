from views.models import View


def test_view_model(create_user, create_organization):
    user = create_user(username="user1")
    org = create_organization(name="organization1", user=user)

    view = View(
        name="myview", query="description:foobar", privacy="public", organization=org
    )
    assert view.name == "myview"
    assert view.query == "description:foobar"
    assert view.privacy == "public"
    assert view.organization == org
    assert view.user is None

    view = View(
        name="myview",
        query="description:foobar",
        privacy="public",
        organization=org,
        user=user,
    )
    assert view.name == "myview"
    assert view.query == "description:foobar"
    assert view.privacy == "public"
    assert view.organization == org
    assert view.user == user
