import pytest
from werkzeug.exceptions import NotFound
from flask_paginate import Pagination
from flask_sqlalchemy import Pagination as PaginationSQLAlchemy

from opencve.controllers.base import BaseController
from opencve.models.cve import Cve


class TestController(BaseController):
    model = Cve
    order = Cve.created_at.desc()
    per_page_param = "CVES_PER_PAGE"
    schema = {
        "str": {"type": str, "default": "foobar"},
        "int": {"type": int, "default": 1234},
    }


def test_parse_args():
    args = TestController.parse_args({})
    assert args == {"page": 1}
    args = TestController.parse_args({"page": 2})
    assert args == {"page": 2}
    args = TestController.parse_args({"undeclared_key": "value"})
    assert args == {"page": 1}
    args = TestController.parse_args({"str": "value"})
    assert args == {"page": 1, "str": "value"}
    args = TestController.parse_args({"str": 1})
    assert args == {"page": 1, "str": "1"}
    args = TestController.parse_args({"int": 1})
    assert args == {"page": 1, "int": 1}
    args = TestController.parse_args({"int": 1})
    assert args == {"page": 1, "int": 1}
    args = TestController.parse_args({"int": "not_integer"})
    assert args == {"page": 1, "int": 1234}
    args = TestController.parse_args({"page": 10, "str": "foo", "int": 100})
    assert args == {"page": 10, "str": "foo", "int": 100}


def test_get(create_cve):
    with pytest.raises(NotFound):
        TestController.get({"cve_id": "CVE-2018-18074"})

    create_cve("CVE-2018-18074")
    obj = TestController.get({"cve_id": "CVE-2018-18074"})
    assert isinstance(obj, Cve)
    assert obj.cve_id == "CVE-2018-18074"


def test_list(app, create_cve):
    with app.test_request_context():
        objects, metas, pagination = TestController.list()
        assert isinstance(objects, PaginationSQLAlchemy)
        assert isinstance(pagination, Pagination)
        assert objects.items == []
        assert metas == {}

    create_cve("CVE-2018-18074")
    create_cve("CVE-2020-35188")
    with app.test_request_context():
        objects, _, _ = TestController.list()
        assert len(objects.items) == 2
        assert sorted([cve.cve_id for cve in objects.items]) == [
            "CVE-2018-18074",
            "CVE-2020-35188",
        ]


def test_list_items(app, create_cve):
    create_cve("CVE-2018-18074")
    create_cve("CVE-2020-35188")
    with app.test_request_context():
        objects = TestController.list_items()
        assert len(objects) == 2
        assert sorted([cve.cve_id for cve in objects]) == [
            "CVE-2018-18074",
            "CVE-2020-35188",
        ]
