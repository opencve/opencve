from pathlib import Path

import pytest
from django.test import override_settings

from changes.models import Change


@pytest.mark.django_db
def test_change_model(create_cve, open_file):
    cve = create_cve("CVE-2024-31331")
    change = Change.objects.filter(id="c8b1dcac-1137-4d07-b045-1903de09c7d9").first()

    # Attributes
    assert change.path == "2024/CVE-2024-31331.json"
    assert change.commit == "a" * 40
    assert change.types == ["weaknesses"]
    assert change.cve == cve

    # Properties
    with override_settings(KB_REPO_PATH="/foo/bar"):
        assert change.full_path == Path("/foo/bar/2024/CVE-2024-31331.json")

    kb_data = open_file("kb/2024/CVE-2024-31331.json")
    assert change.kb_data == kb_data

    assert change.change_data == {
        "created": "2024-10-25T19:00:00+00:00",
        "data": [
            {"details": {"added": [], "removed": ["CWE-783"]}, "type": "weaknesses"}
        ],
        "id": "c8b1dcac-1137-4d07-b045-1903de09c7d9",
    }


@pytest.mark.django_db
def test_change_model_previous_change(create_cve, open_file):
    cve = create_cve("CVE-2024-31331")
    change_1 = Change.objects.filter(id="17d98772-fcde-469c-9694-7f9080da3747").first()
    change_2 = Change.objects.filter(id="c8b1dcac-1137-4d07-b045-1903de09c7d9").first()

    assert not change_1.get_previous_change()
    assert change_2.get_previous_change() == change_1
