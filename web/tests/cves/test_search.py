import pytest
import pyparsing as pp
from django.db.models import Q
from django.contrib.auth.models import AnonymousUser
from unittest.mock import Mock

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
    CweFilter,
    ProjectFilter,
    KevFilter,
    EpssFilter,
)
from users.models import UserTag


@pytest.mark.parametrize(
    "input,output",
    [
        ([">", ">=", "<", "<="], ">, >=, < or <="),
        ([">", ">=", "<"], ">, >= or <"),
        ([">", ">="], "> or >="),
        ([">"], "'>'"),
        (["!=", "!:"], "!= or !:"),
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


def test_string_filter_negation():
    filter = StringFilter("foo", "not_exact", "bar", None)
    assert filter.execute() == ~Q(foo__exact="bar")

    filter = StringFilter("foo", "not_icontains", "bar", None)
    assert filter.execute() == ~Q(foo__icontains="bar")


def test_cwe_filter_bad_query():
    filter = CweFilter("cwe", "lt", "CWE-123", None)
    with pytest.raises(BadQueryException):
        filter.execute()


def test_cwe_filter():
    filter = CweFilter("cwe", "icontains", "CWE-89", None)
    assert filter.execute() == Q(weaknesses__icontains="CWE-89")


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


def test_vendor_filter_with_backslash():
    filter = VendorFilter("foo", "icontains", "micro\\soft", None)
    assert filter.execute() == Q(vendors__contains="micro\\\\soft")


def test_product_filter_bad_query():
    filter = ProductFilter("foo", "lt", "android", None)
    with pytest.raises(BadQueryException):
        filter.execute()


def test_product_filter():
    filter = ProductFilter("foo", "icontains", "android", None)
    assert filter.execute() == Q(vendors__icontains="$PRODUCT$android")


def test_product_filter_with_backslash():
    filter = ProductFilter("foo", "icontains", "android\\", None)
    assert filter.execute() == Q(vendors__icontains="$PRODUCT$android\\\\")


def test_usertag_filter_anonymous_user():
    filter = UserTagFilter("userTag", "icontains", "foobar", AnonymousUser())
    with pytest.raises(BadQueryException) as excinfo:
        filter.execute()
    assert "You must be logged in to use the 'userTag' filter." in str(excinfo.value)


def test_usertag_filter_bad_query(create_user):
    user = create_user()
    filter = UserTagFilter("foo", "lt", "foobar", user)
    with pytest.raises(BadQueryException):
        filter.execute()


def test_usertag_filter_tag_not_found(create_user):
    user = create_user()
    filter = UserTagFilter("foo", "icontains", "foobar", user)
    with pytest.raises(BadQueryException) as excinfo:
        filter.execute()
    assert "The tag 'foobar' does not exist." in str(excinfo.value)


def test_usertag_filter(create_user):
    user = create_user()
    UserTag.objects.create(name="test", user=user)

    filter = UserTagFilter("foo", "icontains", "test", user)
    assert filter.execute() == Q(cve_tags__tags__contains="test", cve_tags__user=user)


def test_project_filter_anonymous_user():
    filter = ProjectFilter("project", "icontains", "foobar", AnonymousUser())
    with pytest.raises(BadQueryException) as excinfo:
        filter.execute()
    assert "You must be logged in to use the 'project' filter." in str(excinfo.value)


def test_project_filter_bad_query(create_user, create_organization, create_project):
    user = create_user()
    org = create_organization("orga", user)
    project = create_project(
        name="proj1", organization=org, vendors=["foo"], products=["bar"]
    )
    request = Mock()
    request.user = user
    request.current_organization = org

    filter = ProjectFilter("project", "exact", project.name, user, request)
    with pytest.raises(BadQueryException) as excinfo:
        filter.execute()
    assert "The operator '=' is not supported for the project field (use ':')" in str(
        excinfo.value
    )


def test_project_filter_project_not_found(create_user, create_organization):
    user = create_user()
    org = create_organization("orga", user)
    request = Mock()
    request.user = user
    request.current_organization = org

    filter = ProjectFilter("project", "icontains", "doesnotexist", user, request)
    with pytest.raises(BadQueryException) as excinfo:
        filter.execute()
    assert "The project 'doesnotexist' does not exist." in str(excinfo.value)


def test_project_filter(create_user, create_organization, create_project):
    user = create_user()
    org = create_organization("orga", user)
    vendors = ["foo", "bar"]
    products = ["baz"]
    project = create_project(
        name="proj1", organization=org, vendors=vendors, products=products
    )
    request = Mock()
    request.user = user
    request.current_organization = org

    filter = ProjectFilter("project", "icontains", project.name, user, request)
    assert filter.execute() == Q(vendors__has_any_keys=vendors + products)


def test_kev_filter_bad_query():
    filter = KevFilter("kev", "gt", "true", None)
    with pytest.raises(BadQueryException):
        filter.execute()


def test_kev_filter_invalid_value():
    filter = KevFilter("kev", "icontains", "maybe", None)
    with pytest.raises(BadQueryException) as excinfo:
        filter.execute()
    assert "kev only supports true or false as value." in str(excinfo.value)


def test_kev_filter_true():
    filter = KevFilter("kev", "icontains", "true", None)
    assert filter.execute() == Q(metrics__kev__data__dateAdded__isnull=False)


def test_kev_filter_false():
    filter = KevFilter("kev", "icontains", "false", None)
    assert filter.execute() == Q(metrics__kev__data__dateAdded__isnull=True)


def test_kev_filter_case_insensitive():
    filter = KevFilter("kev", "icontains", "TRUE", None)
    assert filter.execute() == Q(metrics__kev__data__dateAdded__isnull=False)

    filter = KevFilter("kev", "icontains", "False", None)
    assert filter.execute() == Q(metrics__kev__data__dateAdded__isnull=True)


def test_epss_filter_bad_query():
    filter = EpssFilter("epss", "icontains", "0.5", None)
    with pytest.raises(BadQueryException):
        filter.execute()


def test_epss_filter_invalid_value():
    filter = EpssFilter("epss", "exact", "invalid", None)
    with pytest.raises(BadQueryException) as excinfo:
        filter.execute()
    assert "The EPSS value 'invalid' is invalid (only numbers are accepted)." in str(
        excinfo.value
    )


def test_epss_filter_out_of_range():
    filter = EpssFilter("epss", "exact", "-1", None)
    with pytest.raises(BadQueryException) as excinfo:
        filter.execute()
    assert "The EPSS value '-1' is invalid (must be between 0 and 100)." in str(
        excinfo.value
    )

    filter = EpssFilter("epss", "exact", "101", None)
    with pytest.raises(BadQueryException) as excinfo:
        filter.execute()
    assert "The EPSS value '101' is invalid (must be between 0 and 100)." in str(
        excinfo.value
    )


def test_epss_filter_decimal_values():
    filter = EpssFilter("epss", "exact", "0.5", None)
    assert filter.execute() == Q(metrics__epss__data__score__exact=0.5)

    filter = EpssFilter("epss", "gt", "0.8", None)
    assert filter.execute() == Q(metrics__epss__data__score__gt=0.8)

    filter = EpssFilter("epss", "gte", "0.9", None)
    assert filter.execute() == Q(metrics__epss__data__score__gte=0.9)

    filter = EpssFilter("epss", "lt", "0.3", None)
    assert filter.execute() == Q(metrics__epss__data__score__lt=0.3)

    filter = EpssFilter("epss", "lte", "0.7", None)
    assert filter.execute() == Q(metrics__epss__data__score__lte=0.7)


def test_epss_filter_percentage_conversion():
    # Test that percentage values (>1) are converted to decimal
    filter = EpssFilter("epss", "exact", "50", None)
    assert filter.execute() == Q(metrics__epss__data__score__exact=0.5)

    filter = EpssFilter("epss", "gt", "80", None)
    assert filter.execute() == Q(metrics__epss__data__score__gt=0.8)

    filter = EpssFilter("epss", "gte", "90", None)
    assert filter.execute() == Q(metrics__epss__data__score__gte=0.9)

    filter = EpssFilter("epss", "lt", "30", None)
    assert filter.execute() == Q(metrics__epss__data__score__lt=0.3)

    filter = EpssFilter("epss", "lte", "70", None)
    assert filter.execute() == Q(metrics__epss__data__score__lte=0.7)


def test_epss_filter_edge_cases():
    # Test edge cases: 0, 1, and 100
    filter = EpssFilter("epss", "exact", "0", None)
    assert filter.execute() == Q(metrics__epss__data__score__exact=0.0)

    filter = EpssFilter("epss", "exact", "1", None)
    assert filter.execute() == Q(metrics__epss__data__score__exact=1.0)

    filter = EpssFilter("epss", "exact", "100", None)
    assert filter.execute() == Q(metrics__epss__data__score__exact=1.0)


def test_usertag_filter_anonymous_user():
    filter = UserTagFilter("userTag", "icontains", "foobar", AnonymousUser())
    with pytest.raises(BadQueryException) as excinfo:
        filter.execute()
    assert "You must be logged in to use the 'userTag' filter." in str(excinfo.value)


def test_search_init(create_user):
    user = create_user()
    q = "description:python"
    request = Mock()
    request.user = user

    search = Search(q, request)
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


def test_search_parse_jql_with_special_chars_in_value():
    search = Search("")
    query = "product:some.product-1_beta"
    parsed_query = search.parse_jql(query)
    expected_parsed = [
        "product",
        ":",
        "some.product-1_beta",
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
