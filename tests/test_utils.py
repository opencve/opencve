from opencve.constants import PRODUCT_SEPARATOR
from opencve.extensions import db
from opencve.utils import (
    convert_cpes,
    flatten_vendors,
    get_cwes,
    get_cwes_details,
    get_vendors_letters,
)
from opencve.models.cwe import Cwe


def test_convert_empty_conf():
    assert convert_cpes({}) == {}


def test_convert_simple_conf(open_file):
    conf = open_file("configurations/simple.json")
    assert convert_cpes(conf) == {"foo": ["bar"]}


def test_convert_conf_multiple_products(open_file):
    conf = open_file("configurations/multiple_products.json")
    vendors = convert_cpes(conf)
    vendors["foo"] = sorted(vendors["foo"])
    assert vendors == {"foo": ["bar", "baz"]}


def test_convert_conf_multiple_vendors(open_file):
    conf = open_file("configurations/multiple_vendors.json")
    vendors = convert_cpes(conf)
    vendors["foo"] = sorted(vendors["foo"])
    assert len(vendors) == 2
    assert vendors["foo"] == ["bar", "baz"]
    assert vendors["bar"] == ["baz"]


def test_convert_conf_nested(open_file):
    conf = open_file("configurations/nested.json")
    vendors = convert_cpes(conf)
    vendors["foo"] = sorted(vendors["foo"])
    assert vendors == {"foo": ["bar", "baz"], "bar": ["baz"]}


def test_flatten_empty_vendors():
    assert flatten_vendors({}) == []


def test_flatten_simple_vendor():
    assert flatten_vendors({"foo": ["bar"]}) == ["foo", f"foo{PRODUCT_SEPARATOR}bar"]


def test_flatten_multiple_products():
    assert flatten_vendors({"foo": ["bar", "baz"]}) == [
        "foo",
        f"foo{PRODUCT_SEPARATOR}bar",
        f"foo{PRODUCT_SEPARATOR}baz",
    ]


def test_flatten_multiple_vendors():
    assert flatten_vendors({"foo": ["bar", "baz"], "bar": ["baz"]}) == [
        "foo",
        f"foo{PRODUCT_SEPARATOR}bar",
        f"foo{PRODUCT_SEPARATOR}baz",
        "bar",
        f"bar{PRODUCT_SEPARATOR}baz",
    ]


def test_get_cwes():
    problems = [
        {"lang": "en", "value": "CWE-732"},
        {"lang": "en", "value": "CWE-311"},
        {"lang": "en", "value": "CWE-532"},
    ]
    assert sorted(get_cwes(problems)) == ["CWE-311", "CWE-532", "CWE-732"]

    problems = []
    assert sorted(get_cwes(problems)) == []

    problems = [
        {"lang": "en", "value": "CWE-732"},
        {"lang": "en", "value": "CWE-732"},
        {"lang": "en", "value": "CWE-532"},
    ]
    assert sorted(get_cwes(problems)) == ["CWE-532", "CWE-732"]


def test_get_cwes_details():
    db.session.add(
        Cwe(cwe_id="CWE-1", name="Name of CWE-1", description="Description of CWE-1")
    )
    db.session.add(
        Cwe(cwe_id="CWE-2", name="Name of CWE-2", description="Description of CWE-2")
    )
    db.session.commit()

    cwes = get_cwes_details(
        [{"lang": "en", "value": "CWE-1"}, {"lang": "en", "value": "CWE-2"}]
    )
    assert cwes == {"CWE-1": "Name of CWE-1", "CWE-2": "Name of CWE-2"}

    cwes = get_cwes_details(
        [
            {"lang": "en", "value": "CWE-1"},
            {"lang": "en", "value": "CWE-1"},
            {"lang": "en", "value": "CWE-2"},
        ]
    )
    assert cwes == {"CWE-1": "Name of CWE-1", "CWE-2": "Name of CWE-2"}

    cwes = get_cwes_details([{"lang": "en", "value": "CWE-3"}])
    assert cwes == {"CWE-3": None}


def test_get_vendors_letters():
    assert "".join(get_vendors_letters()) == "abcdefghijklmnopqrstuvwxyz@0123456789"
