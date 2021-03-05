import pytest
from werkzeug.exceptions import NotFound

from opencve.controllers.cwes import CweController


def test_metas(app):
    with app.test_request_context():
        _, metas, _ = CweController.list()
    assert metas == {}


def test_list(app, create_cwes):
    create_cwes(["CWE-1", "CWE-2"])

    with app.test_request_context():
        cwes = CweController.list_items()
    assert len(cwes) == 2
    assert sorted([c.cwe_id for c in cwes]) == ["CWE-1", "CWE-2"]


def test_list_paginated(app, create_cwes):
    old = app.config["CWES_PER_PAGE"]
    app.config["CWES_PER_PAGE"] = 3

    create_cwes(["CWE-1", "CWE-2", "CWE-3", "CWE-4"])

    with app.test_request_context():
        cwes = CweController.list_items()
        assert sorted([c.cwe_id for c in cwes]) == ["CWE-2", "CWE-3", "CWE-4"]
        cwes = CweController.list_items({"page": 2})
        assert sorted([c.cwe_id for c in cwes]) == ["CWE-1"]

    app.config["CWES_PER_PAGE"] = old


@pytest.mark.parametrize(
    "args,result",
    [
        ({"search": "nonexistingkeyword"}, []),
        ({"search": "cwe-1"}, ["CWE-1"]),
        ({"search": "CWE-1"}, ["CWE-1"]),
        ({"search": " cWe-1 "}, ["CWE-1"]),
        ({"search": "2"}, ["CWE-2"]),
        ({"search": "credentials"}, ["CWE-522"]),
    ],
)
def test_by_search(app, create_cwes, create_cwe, args, result):
    create_cwes(["CWE-1", "CWE-2"])
    create_cwe(
        "CWE-522",
        "Insufficiently Protected Credentials",
        "The product transmits...",
    )

    with app.test_request_context():
        cwes = CweController.list_items(args)
    assert sorted([c.cwe_id for c in cwes]) == result
