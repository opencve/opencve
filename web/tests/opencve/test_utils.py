import json

from opencve.utils import get_resource_label, normalize_pk_for_model, safe_load_json
from organizations.models import Organization
from django.contrib.contenttypes.models import ContentType


def test_normalize_pk_for_model_handles_uuid_int_and_str():
    class DummyUUIDPk:
        pk = None

    # For UUID‑like strings we should get a UUID instance
    uuid_str = "70e7b5f9-1b5b-4a7a-9f0e-5e4b3a2c1d0f"
    assert str(normalize_pk_for_model(DummyUUIDPk, uuid_str)) == uuid_str

    # For integers we get an int
    assert normalize_pk_for_model(DummyUUIDPk, "42") == 42

    # Non‑convertible values are returned as string
    assert normalize_pk_for_model(DummyUUIDPk, "foo") == "foo"


def test_safe_load_json_dict_string_and_invalid():
    data = {"foo": "bar"}
    assert safe_load_json(data) is data
    assert safe_load_json(json.dumps(data)) == data
    assert safe_load_json("") is None
    assert safe_load_json("not-json") is None


def test_get_resource_label_known_and_unknown(db):
    ct_org = ContentType.objects.get_for_model(Organization)
    assert get_resource_label(ct_org) == "Organization"

    class Dummy:
        app_label = "foo"
        model = "some_model"

    # Fallback to title‑cased model name
    assert get_resource_label(Dummy()) == "Some Model"

    # None content type returns empty string
    assert get_resource_label(None) == ""
