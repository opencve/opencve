from bs4 import BeautifulSoup
from django.test import override_settings
from django.urls import reverse


@override_settings(ENABLE_ONBOARDING=False)
def test_organization_middleware_without_organization(auth_client, create_user):
    user = create_user(username="john")
    client = auth_client(user)

    response = client.get(reverse("cves"))

    request = response.wsgi_request
    assert not request.current_organization
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
    session["current_organization_id"] = str(orga2.id)
    session.save()

    response = client.get(reverse("cves"), follow=True)
    soup = BeautifulSoup(response.content, features="html.parser")
    content = soup.find("select", {"class": "select2-organizations"}).find(
        "option", selected=True
    )
    request = response.wsgi_request

    assert content.text == orga2.name
    assert request.current_organization == orga2
    assert request.user_organizations == [orga1, orga2]

    # Without saved organization, the first one is chosen
    session = client.session
    del session["current_organization_id"]
    session.save()

    response = client.get(reverse("cves"), follow=True)
    soup = BeautifulSoup(response.content, features="html.parser")
    content = soup.find("select", {"class": "select2-organizations"}).find(
        "option", selected=True
    )
    request = response.wsgi_request

    assert content.text == orga1.name
    assert request.current_organization == orga1
    assert request.user_organizations == [orga1, orga2]


@override_settings(ENABLE_ONBOARDING=False)
def test_organization_middleware_load_from_url(
    auth_client, create_user, create_organization, create_project
):
    user = create_user(username="john")
    client = auth_client(user)
    org_foo = create_organization(name="org_foo", user=user)
    org_bar = create_organization(name="org_bar", user=user)
    org_unknown = create_organization(name="org_unknown")

    # Urls contains the org_foo organization
    response = client.get(reverse("edit_organization", kwargs={"org_name": "org_foo"}))
    soup = BeautifulSoup(response.content, features="html.parser")
    content = soup.find("select", {"class": "select2-organizations"}).find(
        "option", selected=True
    )
    request = response.wsgi_request

    assert content.text == "org_foo"
    assert request.current_organization == org_foo
    assert request.user_organizations == [org_bar, org_foo]

    # Now we switch to the org_bar organization
    response = client.get(reverse("edit_organization", kwargs={"org_name": "org_bar"}))
    soup = BeautifulSoup(response.content, features="html.parser")
    content = soup.find("select", {"class": "select2-organizations"}).find(
        "option", selected=True
    )
    request = response.wsgi_request

    assert content.text == "org_bar"
    assert request.current_organization == org_bar
    assert request.user_organizations == [org_bar, org_foo]

    # But user can't access org_unknown organization as he's not member of it
    response = client.get(
        reverse("edit_organization", kwargs={"org_name": "org_unknown"})
    )
    assert response.status_code == 404
