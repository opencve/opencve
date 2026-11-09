from types import SimpleNamespace

import pytest
from django.test import override_settings

from projects.models import AutomationRunResult
from projects.views import (
    _execution_overview_status,
    _project_subscribed_cve_queryset,
)


class _ResultsList:
    def __init__(self, items):
        self._items = items

    def all(self):
        return self._items


def test_execution_overview_status_never_run():
    """Return a neutral label when an automation was never executed."""
    assert _execution_overview_status(None) == (None, "Never")


def test_execution_overview_status_no_results():
    """Return muted when an execution has no stored results."""
    execution = SimpleNamespace(results=_ResultsList([]))
    assert _execution_overview_status(execution) == ("muted", "No results")


def test_execution_overview_status_failed():
    """Prefer failed when any result failed."""
    execution = SimpleNamespace(
        results=_ResultsList(
            [
                SimpleNamespace(status=AutomationRunResult.STATUS_SUCCESS),
                SimpleNamespace(status=AutomationRunResult.STATUS_FAILED),
            ]
        )
    )
    assert _execution_overview_status(execution) == ("failed", "Failed")


def test_execution_overview_status_success():
    """Return success when at least one result succeeded and none failed."""
    execution = SimpleNamespace(
        results=_ResultsList(
            [SimpleNamespace(status=AutomationRunResult.STATUS_SUCCESS)]
        )
    )
    assert _execution_overview_status(execution) == ("success", "Success")


@override_settings(ENABLE_ONBOARDING=False)
def test_project_subscribed_cve_queryset_empty_without_subscriptions(
    create_organization, create_user, create_project
):
    """Return no CVEs when the project has no subscription vendors or products."""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="p1", organization=org, vendors=[], products=[])
    assert _project_subscribed_cve_queryset(project).count() == 0


@override_settings(ENABLE_ONBOARDING=False)
def test_project_subscribed_cve_queryset_filters_by_subscription(
    create_organization, create_user, create_project, create_cve
):
    """Return CVEs whose vendor keys overlap project subscriptions."""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(
        name="p1", organization=org, vendors=["git-scm"], products=[]
    )
    create_cve("CVE-2023-22490")
    create_cve("CVE-2021-44228")
    qs = _project_subscribed_cve_queryset(project)
    assert qs.filter(cve_id="CVE-2023-22490").exists()
    assert not qs.filter(cve_id="CVE-2021-44228").exists()
