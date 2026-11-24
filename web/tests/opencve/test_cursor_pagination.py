import hashlib
import json
import re
import uuid
from datetime import timedelta

import pytest
from django.core.cache import cache
from django.test import RequestFactory
from django.urls import reverse
from django.utils import timezone

from cves.models import Cve, Weakness
from opencve.cursor_pagination import (
    OPAQUE_CURSOR_MAX_LEN,
    cached_queryset_count,
    cve_list_count_cache_key,
    cve_list_page_requires_auth,
    decode_opaque_cursor,
    encode_opaque_cursor,
    paginate_cve_queryset,
    paginate_weakness_queryset,
    parse_page_number,
    total_pages,
    weakness_list_count_cache_key,
)


@pytest.fixture(autouse=True)
def clear_django_cache():
    cache.clear()
    yield


def create_cves_for_keyset_pagination(count, *, id_offset=0):
    """Insert CVE rows without KB JSON fixtures (pagination tests only)."""
    base_time = timezone.now()
    cves = []
    for index in range(count):
        cve = Cve.objects.create(
            cve_id=f"CVE-2099-{id_offset + index:05d}",
            title=f"Pagination test CVE {index}",
            description="Cursor pagination test fixture",
            vendors=[],
            weaknesses=[],
            metrics={},
        )
        Cve.objects.filter(pk=cve.pk).update(
            updated_at=base_time - timedelta(minutes=index)
        )
        cves.append(cve)
    return cves


def test_total_pages_zero():
    assert total_pages(0, page_size=20) == 0


@pytest.mark.parametrize(
    "raw_value,expected",
    [
        (None, 1),
        ("", 1),
        ("1", 1),
        ("2", 2),
        ("abc", 1),
        ("1.5", 1),
        (True, 1),
        ("0", 1),
        ("-1", 1),
    ],
)
def test_parse_page_number(raw_value, expected):
    assert parse_page_number(raw_value) == expected


def test_cve_list_count_cache_key_user_scoped_never_matches_public():
    factory = RequestFactory()
    public = factory.get("/cve/", {"q": "vendor:debian"})
    scoped = factory.get("/cve/", {"q": "userTag:test"})
    scoped.user = type("User", (), {"is_authenticated": False})()
    assert cve_list_count_cache_key(public) != cve_list_count_cache_key(scoped)


def test_decode_opaque_cursor_rejects_oversized_token():
    token = "A" * (OPAQUE_CURSOR_MAX_LEN + 1)
    assert decode_opaque_cursor(token) is None


def test_cve_list_count_cache_key_scopes_user_tag_queries():
    factory = RequestFactory()
    request_a = factory.get("/cve/", {"q": "userTag:test"})
    request_b = factory.get("/cve/", {"q": "userTag:test"})
    request_a.user = type("User", (), {"is_authenticated": True, "pk": 1})()
    request_b.user = type("User", (), {"is_authenticated": True, "pk": 2})()
    assert cve_list_count_cache_key(request_a) != cve_list_count_cache_key(request_b)


def test_cve_list_count_cache_key_scopes_tag_param_by_user(create_user):
    factory = RequestFactory()
    user_a = create_user(username="cache_user_a")
    user_b = create_user(username="cache_user_b")
    request_a = factory.get("/cve/", {"tag": "production"})
    request_b = factory.get("/cve/", {"tag": "production"})
    request_a.user = user_a
    request_b.user = user_b
    assert cve_list_count_cache_key(request_a) != cve_list_count_cache_key(request_b)


def test_cve_list_count_cache_key_scopes_project_query_by_org(
    create_user, create_organization
):
    factory = RequestFactory()
    user = create_user(username="cache_project_user")
    org_a = create_organization(name="cache_org_a", user=user)
    org_b = create_organization(name="cache_org_b", user=user)
    request_a = factory.get("/cve/", {"q": "project:shared-name"})
    request_b = factory.get("/cve/", {"q": "project:shared-name"})
    request_a.user = user
    request_b.user = user
    request_a.current_organization = org_a
    request_b.current_organization = org_b
    assert cve_list_count_cache_key(request_a) != cve_list_count_cache_key(request_b)


def test_weakness_list_count_cache_key_search():
    factory = RequestFactory()
    request = factory.get("/weaknesses/", {"search": "xss"})
    digest = hashlib.sha256(b"search=xss").hexdigest()
    assert weakness_list_count_cache_key(request) == f"weakness_list_count:{digest}"


@pytest.mark.parametrize(
    "query_string,expected",
    [
        ("", False),
        ("q=vendor:debian", False),
        ("tag=mytag", True),
        ("q=userTag:mytag", True),
        ("q=project:foo", True),
    ],
)
def test_cve_list_page_requires_auth(query_string, expected):
    factory = RequestFactory()
    request = factory.get(f"/cve/page/?{query_string}")
    assert cve_list_page_requires_auth(request) is expected


def test_cve_list_page_view_requires_auth_for_user_tag(db, client):
    response = client.get(reverse("cves_page"), {"q": "userTag:foo"})
    assert response.status_code == 401
    assert "error" in response.json()


def test_paginate_cve_queryset_forward(db):
    create_cves_for_keyset_pagination(25)

    queryset = Cve.objects.order_by("-updated_at")
    first = paginate_cve_queryset(queryset, after=None, before=None, limit=20)
    assert len(first.items) == 20
    assert first.has_next is True
    assert first.has_previous is False
    assert first.after

    second = paginate_cve_queryset(queryset, after=first.after, before=None, limit=20)
    assert len(second.items) == 5
    assert second.has_next is False
    assert second.has_previous is True


def test_paginate_cve_queryset_backward(db):
    create_cves_for_keyset_pagination(25, id_offset=100)

    queryset = Cve.objects.order_by("-updated_at")
    first = paginate_cve_queryset(queryset, after=None, before=None, limit=20)
    second = paginate_cve_queryset(queryset, after=first.after, before=None, limit=20)
    previous = paginate_cve_queryset(
        queryset, after=None, before=second.before, limit=20
    )
    assert [cve.cve_id for cve in previous.items] == [cve.cve_id for cve in first.items]


def test_paginate_weakness_queryset(db):
    for index in range(25):
        Weakness.objects.create(
            cwe_id=f"CWE-{index:04d}",
            name=f"Weakness {index:02d}",
        )

    queryset = Weakness.objects.all()
    first = paginate_weakness_queryset(queryset, after=None, before=None, limit=20)
    assert len(first.items) == 20
    second = paginate_weakness_queryset(
        queryset, after=first.after, before=None, limit=20
    )
    assert len(second.items) == 5


def test_paginate_weakness_queryset_null_names(db):
    Weakness.objects.create(cwe_id="CWE-9001", name="Named")
    Weakness.objects.create(cwe_id="CWE-9002", name=None)

    queryset = Weakness.objects.all()
    first = paginate_weakness_queryset(queryset, after=None, before=None, limit=1)
    second = paginate_weakness_queryset(
        queryset, after=first.after, before=None, limit=1
    )
    assert len(first.items) == 1
    assert len(second.items) == 1
    assert first.items[0].cwe_id != second.items[0].cwe_id


def test_paginate_weakness_queryset_backward(db):
    for index in range(25):
        Weakness.objects.create(
            cwe_id=f"CWE-B-{index:04d}",
            name=f"Weakness B {index:02d}",
        )

    queryset = Weakness.objects.all()
    first = paginate_weakness_queryset(queryset, after=None, before=None, limit=20)
    second = paginate_weakness_queryset(
        queryset, after=first.after, before=None, limit=20
    )
    previous = paginate_weakness_queryset(
        queryset, after=None, before=second.before, limit=20
    )
    assert [row.cwe_id for row in previous.items] == [row.cwe_id for row in first.items]


def test_cached_queryset_count_uses_cache(db, create_cve, django_assert_num_queries):
    create_cve("CVE-2024-31331")
    queryset = Cve.objects.all()
    cache_key = f"test_count:{uuid.uuid4()}"

    with django_assert_num_queries(1):
        first = cached_queryset_count(queryset, cache_key, ttl=30)
    with django_assert_num_queries(0):
        second = cached_queryset_count(queryset, cache_key, ttl=30)
    assert first == second == 1


def test_cve_list_page_view_invalid_page_defaults_to_one(db, create_cve, client):
    create_cve("CVE-2024-31331")
    response = client.get(f"{reverse('cves_page')}?page=not-a-page")
    assert response.status_code == 200
    assert response.json()["page"] == 1


def test_weakness_list_page_view_invalid_page_defaults_to_one(db, client):
    Weakness.objects.create(cwe_id="CWE-INVALID-PAGE", name="Test")
    response = client.get(f"{reverse('weaknesses_page')}?page=not-a-page")
    assert response.status_code == 200
    assert response.json()["page"] == 1


def _cve_ids_in_list_html(html):
    return set(re.findall(r"CVE-\d{4}-\d+", html))


def test_cve_list_page_view_pages_do_not_overlap(db, client):
    create_cves_for_keyset_pagination(25, id_offset=200)

    first_response = client.get(reverse("cves_page"), {"page": 1})
    first_payload = first_response.json()
    assert first_payload["has_next"] is True

    second_response = client.get(
        reverse("cves_page"),
        {"page": 2, "after": first_payload["after"]},
    )
    second_payload = second_response.json()

    first_ids = _cve_ids_in_list_html(first_payload["html"])
    second_ids = _cve_ids_in_list_html(second_payload["html"])
    assert first_ids
    assert second_ids
    assert first_ids.isdisjoint(second_ids)


def test_cve_list_view_ignores_page_query_param(db, client):
    create_cves_for_keyset_pagination(25, id_offset=300)

    first_page_response = client.get(reverse("cves"))
    second_page_response = client.get(reverse("cves"), {"page": "2"})

    def initial_state_from_html(response):
        match = re.search(
            r'id="cve-list-initial-state"[^>]*>(.*?)</script>',
            response.content.decode(),
            re.DOTALL,
        )
        assert match
        return json.loads(match.group(1))

    first_state = initial_state_from_html(first_page_response)
    second_state = initial_state_from_html(second_page_response)
    assert first_state["page"] == 1
    assert second_state["page"] == 1
    assert first_state["after"] == second_state["after"]


def test_cve_list_page_view(db, client):
    create_cves_for_keyset_pagination(3, id_offset=400)
    expected_total = Cve.objects.count()
    assert expected_total == 3

    response = client.get(f"{reverse('cves_page')}?page=1")
    assert response.status_code == 200
    payload = response.json()
    assert "html" in payload
    assert payload["page"] == 1
    assert payload["total"] == expected_total


def test_weakness_list_page_view(db, client):
    for index in range(3):
        Weakness.objects.create(cwe_id=f"CWE-Z-{index}", name=f"Name {index}")
    expected_total = Weakness.objects.count()
    assert expected_total == 3

    response = client.get(f"{reverse('weaknesses_page')}?page=1")
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == expected_total
    assert "html" in payload


def test_encode_opaque_cursor_roundtrip():
    token = encode_opaque_cursor(
        {"u": "2025-01-01T00:00:00+00:00", "i": str(uuid.uuid4())}
    )
    assert token
    assert "=" not in token
