from bs4 import BeautifulSoup
from django.test import override_settings
from django.urls import reverse


@override_settings(ENABLE_ONBOARDING=False)
def test_organization_middleware_without_organization(auth_client, create_user):
    user = create_user(username="john")
    client = auth_client(user)

    response = client.get(reverse("cves"))

    request = response.wsgi_request
    assert not request.user_organization
    assert request.user_organizations == []


@override_settings(ENABLE_ONBOARDING=False)
def test_organization_middleware_with_organizations(
    auth_client, create_user, create_organization
):
    user = create_user(username="john")
    orga1 = create_organization(name="orga1", user=user)
    orga2 = create_organization(name="orga2", user=user)
    client = auth_client(user)

    # If an organization is already stored in session, it will be the selected one
    session = client.session
    session["user_organization_id"] = str(orga2.id)
    session.save()

    response = client.get(reverse("cves"), follow=True)
    soup = BeautifulSoup(response.content, features="html.parser")
    content = soup.find("select", {"class": "select2-organizations"}).find(
        "option", selected=True
    )
    request = response.wsgi_request

    assert content.text == orga2.name
    assert request.user_organization == orga2
    assert request.user_organizations == [orga1, orga2]

    # Without saved organization, the first one is chosen
    session = client.session
    del session["user_organization_id"]
    session.save()

    response = client.get(reverse("cves"), follow=True)
    soup = BeautifulSoup(response.content, features="html.parser")
    content = soup.find("select", {"class": "select2-organizations"}).find(
        "option", selected=True
    )
    request = response.wsgi_request

    assert content.text == orga1.name
    assert request.user_organization == orga1
    assert request.user_organizations == [orga1, orga2]
