from unittest.mock import patch

import pytest

from utils import (
    decode_hmap,
    get_chunks,
    merge_projects_changes,
    PRODUCT_SEPARATOR,
    PostgresHook,
    RedisHook,
    run_sql,
    vendors_conf_to_dict,
    vendors_conf_to_flat,
    vendors_dict_to_flat,
    weaknesses_to_flat,
)


def test_vendors_conf_to_dict(open_file):
    assert vendors_conf_to_dict({}) == {}

    # Simple case
    configurations = [
        {
            "nodes": [
                {
                    "cpeMatch": [
                        {"criteria": "cpe:2.3:a:opencveio:opencve:*:*:*:*:*:*:*:*"}
                    ]
                }
            ]
        }
    ]
    assert vendors_conf_to_dict(configurations) == {"opencveio": ["opencve"]}

    # Multiple nodes
    configurations = [
        {
            "nodes": [
                {
                    "cpeMatch": [
                        {"criteria": "cpe:2.3:a:opencveio:opencve:*:*:*:*:*:*:*:*"},
                        {"criteria": "cpe:2.3:a:foo:bar:*:*:*:*:*:*:*:*"},
                    ]
                },
                {"cpeMatch": [{"criteria": "cpe:2.3:a:foo:baz:*:*:*:*:*:*:*:*"}]},
            ]
        }
    ]
    vendors = vendors_conf_to_dict(configurations)
    assert vendors["opencveio"] == ["opencve"]
    assert sorted(vendors["foo"]) == sorted(["bar", "baz"])

    # Real CVE data
    cve_data = open_file("nvd/cves/CVE-2019-14232.json")
    configurations = cve_data.get("configurations")
    assert vendors_conf_to_dict(configurations) == {
        "djangoproject": ["django"],
        "opensuse": ["leap"],
    }


def test_vendors_dict_to_flat(open_file):
    assert (vendors_dict_to_flat({})) == []

    # Simple case
    vendors = {"opencveio": ["opencve"]}
    assert sorted(vendors_dict_to_flat(vendors)) == sorted(
        ["opencveio", f"opencveio{PRODUCT_SEPARATOR}opencve"]
    )

    # Multiple nodes
    vendors = {"opencveio": ["opencve"], "foo": ["bar", "baz"]}
    assert sorted(vendors_dict_to_flat(vendors)) == sorted(
        [
            "opencveio",
            f"opencveio{PRODUCT_SEPARATOR}opencve",
            "foo",
            f"foo{PRODUCT_SEPARATOR}bar",
            f"foo{PRODUCT_SEPARATOR}baz",
        ]
    )


def test_vendors_conf_to_flat(open_file):
    assert vendors_conf_to_flat() == []
    assert vendors_conf_to_flat({}) == []

    # Simple case
    configurations = [
        {
            "nodes": [
                {
                    "cpeMatch": [
                        {"criteria": "cpe:2.3:a:opencveio:opencve:*:*:*:*:*:*:*:*"}
                    ]
                }
            ]
        }
    ]
    assert sorted(vendors_conf_to_flat(configurations)) == sorted(
        ["opencveio", f"opencveio{PRODUCT_SEPARATOR}opencve"]
    )

    # Multiple nodes
    configurations = [
        {
            "nodes": [
                {
                    "cpeMatch": [
                        {"criteria": "cpe:2.3:a:opencveio:opencve:*:*:*:*:*:*:*:*"},
                        {"criteria": "cpe:2.3:a:foo:bar:*:*:*:*:*:*:*:*"},
                    ]
                },
                {"cpeMatch": [{"criteria": "cpe:2.3:a:foo:baz:*:*:*:*:*:*:*:*"}]},
            ]
        }
    ]
    assert sorted(vendors_conf_to_flat(configurations)) == sorted(
        [
            "opencveio",
            f"opencveio{PRODUCT_SEPARATOR}opencve",
            "foo",
            f"foo{PRODUCT_SEPARATOR}bar",
            f"foo{PRODUCT_SEPARATOR}baz",
        ]
    )

    # Real CVE data
    cve_data = open_file("nvd/cves/CVE-2019-14232.json")
    configurations = cve_data.get("configurations")
    assert sorted(vendors_conf_to_flat(configurations)) == sorted(
        [
            "djangoproject",
            "djangoproject$PRODUCT$django",
            "opensuse",
            "opensuse$PRODUCT$leap",
        ]
    )


def test_weaknesses_to_flat(open_file):
    cve = open_file("nvd/cves/CVE-2019-14232.json")
    weaknesses = weaknesses_to_flat(cve["weaknesses"])
    assert weaknesses == ["CWE-400"]

    # Check with multiple CWEs
    weaknesses = weaknesses_to_flat(
        [
            {
                "description": [{"lang": "en", "value": "CWE-123"}],
                "source": "nvd@nist.gov",
                "type": "Primary",
            },
            {
                "description": [{"lang": "en", "value": "CWE-345"}],
                "source": "nvd@nist.gov",
                "type": "Primary",
            },
        ]
    )
    assert sorted(weaknesses) == ["CWE-123", "CWE-345"]


def test_chunks():
    assert get_chunks([], 2) == []
    assert get_chunks(["a"], 2) == [["a"]]
    assert get_chunks(["a", "b"], 2) == [["a"], ["b"]]
    assert get_chunks(["a", "b", "c"], 2) == [["a", "b"], ["c"]]
    assert get_chunks(["a", "b", "c", "d", "e"], 3) == [["a", "b"], ["c", "d"], ["e"]]


@patch.object(PostgresHook, "run")
def test_run_sql(mock):
    query = "INSERT %(foo)s INTO bar"
    parameters = {"foo": "bar"}
    run_sql(query=query, parameters=parameters)
    mock.assert_called_with(sql=query, parameters=parameters)


@pytest.mark.parametrize(
    "input,output",
    [
        ({}, {}),
        ({b"foo": b'["bar"]'}, {"foo": ["bar"]}),
        ({b"foo": b'["bar", "baz"]'}, {"foo": ["bar", "baz"]}),
    ],
)
@patch.object(RedisHook, "get_conn")
def test_decode_hmap(mock, input, output):
    mock().hgetall.return_value = input
    assert decode_hmap("foo") == output


def test_merge_projects_changes():
    projects_subscriptions = {
        "project1": ["foo", "bar"],
        "project2": ["baz"],
        "project3": ["lorem", "foo"],
    }
    vendors_changes = {
        "foo": ["change1", "change2"],
        "bar": ["change3"],
        "oil": ["change1"],
    }
    merged = merge_projects_changes(projects_subscriptions, vendors_changes)
    assert sorted(merged["project1"]) == sorted(["change1", "change2", "change3"])
    assert sorted(merged["project3"]) == sorted(["change1", "change2"])
