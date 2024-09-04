from django.urls import reverse

from cves.models import Cve
from users.models import User, UserTag, CveTag


def test_delete_owner_account(auth_client, create_user, create_organization):
    user = create_user(username="user1")
    create_organization(name="orga1", user=user, owner=True)
    client = auth_client(user)

    delete_url = reverse("delete_account")
    response = client.get(delete_url, follow=True)
    assert response.status_code == 200
    assert response.redirect_chain == [(reverse("settings_account"), 302)]
    assert (
        b"Your account is currently owner of the following organizations: orga1"
        in response.content
    )


def test_delete_member_account(auth_client, create_user):
    user = create_user(username="user1")
    client = auth_client(user)
    delete_url = reverse("delete_account")

    response = client.get(delete_url)
    assert response.status_code == 200
    message = (
        f"Do you really want to delete the <strong>{user.username}</strong> account ?"
    )
    assert message.encode() in response.content

    response = client.post(delete_url, follow=True)
    assert response.status_code == 200
    assert response.redirect_chain == [(reverse("account_login"), 302)]


def test_delete_account_cascade_delete(auth_client, create_user, create_organization):
    user = create_user(username="user1")
    organization = create_organization(name="orga1", user=user, owner=False)
    user_tag = UserTag.objects.create(name="Test Tag", color="#000000", user=user)
    cve = Cve.objects.create(cve_id="CVE-2024-1234")
    CveTag.objects.create(user=user, cve=cve, tags=[user_tag.name])

    user_id = user.id
    assert User.objects.filter(id=user_id).count() == 1
    assert UserTag.objects.filter(user_id=user_id).count() == 1
    assert CveTag.objects.filter(user_id=user_id).count() == 1

    client = auth_client(user)
    delete_url = reverse("delete_account")
    client.post(delete_url)

    assert User.objects.filter(id=user_id).count() == 0
    assert UserTag.objects.filter(user_id=user_id).count() == 0
    assert CveTag.objects.filter(user_id=user_id).count() == 0
