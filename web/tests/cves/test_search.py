import pytest
import pyparsing as pp
from django.db.models import Q
from django.http.response import Http404

from cves.search import (
    BadQueryException,
    CveFilter,
    CvssFilter,
    Filter,
    StringFilter,
    VendorFilter,
    ProductFilter,
    UserTagFilter,
    Search,
)
from users.models import UserTag


@pytest.mark.parametrize(
    "input,output",
    [
        ([">", ">=", "<", "<="], ">, >=, < or <="),
        ([">", ">=", "<"], ">, >= or <"),
        ([">", ">="], "> or >="),
        ([">"], "'>'"),
    ],
)
def test_filter_allowed_operator_str(input, output):
    filter = Filter(None, None, None, None)
    filter.supported_operators = input
    assert filter.allowed_operator_str() == output


def test_filter_execute_success():
    filter = Filter("foo", "exact", None, None)
    filter.supported_operators = ["="]

    with pytest.raises(NotImplementedError):
        filter.execute()


def test_filter_execute_error():
    filter = Filter("foo", "exact", None, None)
    filter.supported_operators = [">=", "<="]

    with pytest.raises(BadQueryException) as excinfo:
        filter.execute()
    assert (
        str(excinfo.value)
        == "The operator '=' is not supported for the foo field (use >= or <=)."
    )


def test_string_filter_bad_query():
    filter = StringFilter("foo", "gt", "bar", None)
    with pytest.raises(BadQueryException):
        filter.execute()


def test_string_filter():
    filter = StringFilter("foo", "exact", "bar", None)
    assert filter.execute() == Q(foo__exact="bar")

    filter = StringFilter("foo", "icontains", "bar", None)
    assert filter.execute() == Q(foo__icontains="bar")


def test_cve_filter_bad_query():
    filter = CveFilter("foo", "gt", "bar", None)
    with pytest.raises(BadQueryException):
        filter.execute()


def test_cve_filter():
    filter = CveFilter("foo", "exact", "bar", None)
    assert filter.execute() == Q(cve_id__exact="bar")

    filter = CveFilter("foo", "icontains", "bar", None)
    assert filter.execute() == Q(cve_id__icontains="bar")


def test_cvss_filter_invalid_integer():
    filter = CvssFilter("cvss40", "exact", "foo", None)

    with pytest.raises(BadQueryException) as excinfo:
        filter.execute()
    assert (
        str(excinfo.value)
        == "The value 'foo' in the query 'cvss40=foo' is invalid (only integers are accepted)."
    )


def test_cvss_filter_bad_query():
    filter = CvssFilter("cvss40", "icontains", 8, None)
    with pytest.raises(BadQueryException):
        filter.execute()


def test_cvss_filter():
    filter = CvssFilter("cvss40", "exact", 8, None)
    assert filter.execute() == Q(metrics__cvssV4_0__data__score__exact=8)

    filter = CvssFilter("cvss40", "gt", 8, None)
    assert filter.execute() == Q(metrics__cvssV4_0__data__score__gt=8)

    filter = CvssFilter("cvss40", "gte", 8, None)
    assert filter.execute() == Q(metrics__cvssV4_0__data__score__gte=8)

    filter = CvssFilter("cvss40", "lt", 8, None)
    assert filter.execute() == Q(metrics__cvssV4_0__data__score__lt=8)

    filter = CvssFilter("cvss40", "lte", 8, None)
    assert filter.execute() == Q(metrics__cvssV4_0__data__score__lte=8)


def test_vendor_filter_bad_query():
    filter = VendorFilter("foo", "lt", "microsoft", None)
    with pytest.raises(BadQueryException):
        filter.execute()


def test_vendor_filter():
    filter = VendorFilter("foo", "icontains", "microsoft", None)
    assert filter.execute() == Q(vendors__contains="microsoft")


def test_product_filter_bad_query():
    filter = ProductFilter("foo", "lt", "android", None)
    with pytest.raises(BadQueryException):
        filter.execute()


def test_product_filter():
    filter = ProductFilter("foo", "icontains", "android", None)
    assert filter.execute() == Q(vendors__icontains="$PRODUCT$android")


def test_usertag_filter_bad_query(create_user):
    user = create_user()
    filter = UserTagFilter("foo", "lt", "foobar", user)
    with pytest.raises(BadQueryException):
        filter.execute()


def test_usertag_filter_tag_not_found(create_user):
    user = create_user()
    filter = UserTagFilter("foo", "icontains", "foobar", user)
    with pytest.raises(Http404):
        filter.execute()


def test_usertag_filter(create_user):
    user = create_user()
    UserTag.objects.create(name="test", user=user)

    filter = UserTagFilter("foo", "icontains", "test", user)
    assert filter.execute() == Q(cve_tags__tags__contains="test", cve_tags__user=user)


def test_search_init(create_user):
    user = create_user()
    q = "description:python"
    search = Search(q, user)
    assert search.q == q
    assert search.user == user
    assert search._query is None
    assert search.error is None


@pytest.mark.parametrize(
    "query, expected_result",
    [
        ("description:python", True),
        ("description:python AND (cvss31>=8 OR cvss40>=8)", True),
        ("vendors:microsoft AND userTag:mytag", True),
        ("invalid query", False),
    ],
)
def test_search_validation(query, expected_result):
    search = Search(query)
    assert search.validate_parsing() == expected_result
    if not expected_result:
        assert isinstance(search.error, pp.ParseException)


def test_search_json_to_django_q():
    search = Search("")
    filter_json = {
        "$and": [
            {"description": {"operator": "icontains", "value": "python"}},
            {
                "$or": [
                    {"cvss31": {"operator": "gte", "value": "8"}},
                    {"cvss40": {"operator": "gte", "value": "8"}},
                ]
            },
        ]
    }

    q_obj = search.json_to_django_q(filter_json)

    expected_q = Q(Q(description__icontains="python")) & (
        Q(Q(metrics__cvssV3_1__data__score__gte=8))
        | Q(Q(metrics__cvssV4_0__data__score__gte=8))
    )

    assert q_obj == expected_q


def test_search_parse_jql():
    search = Search("")
    parsed_query = search.parse_jql("description:python AND (cvss31>=8 OR cvss40>=8)")
    expected_parsed = [
        ["description", ":", "python"],
        "AND",
        [["cvss31", ">=", "8"], "OR", ["cvss40", ">=", "8"]],
    ]
    assert parsed_query == expected_parsed


def test_search_jql_to_json():
    search = Search("")
    parsed_query = [
        ["description", ":", "python"],
        "AND",
        [["cvss31", ">=", "8"], "OR", ["cvss40", ">=", "8"]],
    ]
    json_filter = search.jql_to_json(parsed_query)
    expected_json = {
        "$and": [
            {"description": {"operator": "icontains", "value": "python"}},
            {
                "$or": [
                    {"cvss31": {"operator": "gte", "value": "8"}},
                    {"cvss40": {"operator": "gte", "value": "8"}},
                ]
            },
        ]
    }
    assert json_filter == expected_json
