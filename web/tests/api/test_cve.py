import pytest
from django.urls import reverse


def test_unauthenticated_user(client, auth_client):
    response = client.get(reverse("cve-list"))
    assert response.status_code == 403

    client = auth_client()
    response = client.get(reverse("cve-list"))
    assert response.status_code == 200


@pytest.mark.django_db
def test_list_cves(create_cve, auth_client):
    client = auth_client()
    response = client.get(reverse("cve-list"))
    assert response.json()["results"] == []

    create_cve("CVE-2021-44228")
    response = client.get(reverse("cve-list"))
    assert response.json()["count"] == 1
    assert response.json()["results"] == [
        {
            "created_at": "2021-12-10T00:00:00Z",
            "updated_at": "2024-07-24T17:08:24.167000Z",
            "cve_id": "CVE-2021-44228",
            "description": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.",
        }
    ]

    create_cve("CVE-2022-22965")
    response = client.get(reverse("cve-list"))
    assert response.json()["count"] == 2
    assert response.json()["results"] == [
        {
            "created_at": "2022-03-30T00:00:00Z",
            "updated_at": "2024-07-31T20:10:19.936000Z",
            "cve_id": "CVE-2022-22965",
            "description": "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.",
        },
        {
            "created_at": "2021-12-10T00:00:00Z",
            "updated_at": "2024-07-24T17:08:24.167000Z",
            "cve_id": "CVE-2021-44228",
            "description": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.",
        },
    ]


@pytest.mark.parametrize(
    "params,result",
    [
        ("", ["CVE-2021-44228", "CVE-2022-22965"]),  # no filter
        ("?search=log4j", ["CVE-2021-44228"]),  # text in description
        ("?search=spring", ["CVE-2022-22965"]),  # text in description
        ("?search=44228", ["CVE-2021-44228"]),  # test in CVE ID
        ("?search=oracle", ["CVE-2022-22965"]),  # text in vendors
        ("?weakness=CWE-400", ["CVE-2021-44228"]),
        ("?cvss=low", []),
        ("?cvss=critical", ["CVE-2021-44228", "CVE-2022-22965"]),
        ("?vendor=siemens", ["CVE-2021-44228", "CVE-2022-22965"]),
        ("?vendor=veritas", ["CVE-2022-22965"]),
        ("?vendor=veritas&product=flex_appliance", ["CVE-2022-22965"]),
    ],
)
def test_list_cves_with_filters(create_cve, auth_client, params, result):
    client = auth_client()
    response = client.get(reverse("cve-list"))
    assert response.json()["results"] == []

    create_cve("CVE-2021-44228")
    create_cve("CVE-2022-22965")

    response = client.get(f"{reverse('cve-list')}{params}")
    assert sorted(c["cve_id"] for c in response.json()["results"]) == result


def test_list_cves_filtering_by_not_existing_vendors(create_cve, auth_client):
    client = auth_client()
    create_cve("CVE-2021-44228")

    response = client.get(f"{reverse('cve-list')}?vendor=siemens")
    assert response.status_code == 200
    response = client.get(f"{reverse('cve-list')}?vendor=foobar")
    assert response.status_code == 404

    response = client.get(f"{reverse('cve-list')}?vendor=siemens&product=mendix")
    assert response.status_code == 200
    response = client.get(f"{reverse('cve-list')}?vendor=siemens&product=foobar")
    assert response.status_code == 404


@pytest.mark.django_db
def test_get_cve(create_cve, open_file, auth_client):
    client = auth_client()
    response = client.get(reverse("cve-detail", kwargs={"cve_id": "CVE-2021-44228"}))
    assert response.status_code == 404
    assert response.json() == {"detail": "No Cve matches the given query."}

    create_cve("CVE-2021-44228")
    response = client.get(reverse("cve-detail", kwargs={"cve_id": "CVE-2021-44228"}))
    assert response.status_code == 200
    expected_result = open_file("serialized_cves/CVE-2021-44228.json")
    assert response.json() == expected_result
