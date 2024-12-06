import pytest
from django.contrib import auth
from django.http.request import QueryDict
from django.test import override_settings

from users.models import UserTag, CveTag
from cves.utils import list_filtered_cves


@override_settings(ENABLE_ONBOARDING=False)
@pytest.mark.parametrize(
    "params,result",
    [
        ("", ["CVE-2021-44228", "CVE-2022-22965"]),  # no filter
        ("search=log4j", ["CVE-2021-44228"]),  # text in description
        ("search=spring", ["CVE-2022-22965"]),  # text in description
        ("search=44228", ["CVE-2021-44228"]),  # text in CVE ID
        ("search=oracle", ["CVE-2022-22965"]),  # text in vendors
        ("weakness=CWE-400", ["CVE-2021-44228"]),
        ("cvss=low", []),
        ("cvss=critical", ["CVE-2021-44228", "CVE-2022-22965"]),
        ("vendor=siemens", ["CVE-2021-44228", "CVE-2022-22965"]),
        ("vendor=veritas", ["CVE-2022-22965"]),
        ("vendor=veritas&product=flex_appliance", ["CVE-2022-22965"]),
    ],
)
def test_list_filtered_cves(db, create_cve, client, params, result):
    create_cve("CVE-2021-44228")
    create_cve("CVE-2022-22965")
    user = auth.get_user(client)

    assert (
        sorted([c.cve_id for c in list_filtered_cves(QueryDict(params), user)])
        == result
    )


def test_list_filtered_cves_with_tag(db, create_cve, create_user):
    cve = create_cve("CVE-2021-44228")
    create_cve("CVE-2022-22965")

    user = create_user()
    tag = UserTag.objects.create(name="test", user=user)
    CveTag.objects.create(user=user, cve=cve, tags=[tag.name])

    assert sorted(
        [c.cve_id for c in list_filtered_cves(QueryDict("tag=test"), user)]
    ) == ["CVE-2021-44228"]
