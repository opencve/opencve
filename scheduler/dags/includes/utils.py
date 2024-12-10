import pathlib
from logging import Logger
from typing import Dict, List, Tuple

import more_itertools
from airflow.exceptions import AirflowException
from git.objects.commit import Commit
from git.repo import Repo
from includes.constants import KB_LOCAL_REPO
from pendulum.datetime import DateTime


def divide_list(iterable, n):
    """
    Divide a list into n chunks.

    Examples:
      >>> divide_list(["a", "b", "c", "d"], 5)
      >>> [["a"], ["b"], ["c"], ["d"]]
      >>> divide_list(["a", "b", "c", "d"], 3)
      >>> [["a", "b"], ["c"], ["d"]]
    """
    if len(iterable) <= n:
        return [[p] for p in iterable]

    new_list = []
    for chunk in more_itertools.divide(n, iterable):
        new_list.append(list(chunk))

    return new_list


def group_changes_by_vendor(records):
    """
    This function groups changes by vendors.
    """
    vendors_changes = {}

    for record in records:
        change_id = record[0]
        vendors = record[3]
        for vendor in vendors:
            if vendor not in vendors_changes:
                vendors_changes[vendor] = []
            vendors_changes[vendor].append(change_id)

    return vendors_changes


def format_change_details(records):
    """
    This function transform a list of changes into a dictionary
    """
    return {
        r[0]: {
            "change_id": r[0],
            "change_types": r[1],
            "change_path": r[2],
            "cve_vendors": r[3],
            "cve_id": r[4],
            "cve_metrics": r[5],
        }
        for r in records
    }


def merge_project_subscriptions(records):
    """
    This function returns a list of projects with their associated
    vendors and products.
    """
    projects_subscriptions = {}
    for project in records:
        vendors = project[1]["vendors"] + project[1]["products"]
        if vendors:
            projects_subscriptions[project[0]] = vendors
    return projects_subscriptions


def list_changes_by_project(changes, subscriptions):
    """
    This associates the project subscriptions with their changes.

    Example:
        >>> changes = {
            'vendor1': ['change-uuid-1'],
            'vendor2': ['change-uuid-1', 'change-uuid-2']
        }
        >>> subscriptions = {
            'project-uuid-1': ['vendor1', 'vendor2', 'vendor$PRODUCT$product']
        }
        >>> list_changes_by_project(changes, subscriptions)
        {
            "project-uuid-1": [
                "change-uuid-1",
                "change-uuid-2"
            ]
        }
    """
    projects_changes = {}
    for project, subscriptions in subscriptions.items():

        # Skip the project if no subscription
        if not subscriptions:
            continue

        projects_changes[project] = set()
        for subscription in subscriptions:
            if subscription in changes.keys():
                projects_changes[project].update(changes[subscription])
        projects_changes[project] = list(projects_changes[project])

    return {k: v for k, v in projects_changes.items() if v}


def group_notifications_by_project(records):
    projects_notifications = {}
    for notification in records:
        p_id, p_name, o_name, n_name, n_type, n_conf = notification

        if p_id not in projects_notifications:
            projects_notifications[p_id] = []

        projects_notifications[p_id].append(
            {
                "project_id": p_id,
                "project_name": p_name,
                "organization_name": o_name,
                "notification_name": n_name,
                "notification_type": n_type,
                "notification_conf": n_conf,
            }
        )
    return projects_notifications


def get_dates_from_context(context: Dict) -> Tuple[DateTime, DateTime]:
    start = context.get("data_interval_start")
    end = context.get("data_interval_end").subtract(seconds=1)
    return start, end


def list_commits(logger: Logger, start: DateTime, end: DateTime) -> List[Commit]:
    logger.info("Reading %s repository", KB_LOCAL_REPO)
    repo_path = pathlib.Path(KB_LOCAL_REPO)

    if not all([start, end]):
        raise AirflowException("Start and end intervals must be set")

    # Each DagRun only parses its associated commits (schedule is hourly).
    # We'll use the interval dates to list commits during this period, but
    # git log --before and --after options are both included, so we need to
    # subtract 1 second to the end date in order to avoid duplicates commits.
    end = end.subtract(seconds=1)

    logger.info("Listing commits between %s and %s", start, end)
    repo = Repo(repo_path)
    commits = list(repo.iter_commits(after=start, before=end, reverse=True))

    if not commits:
        logger.info("No commit found")
        return []

    # Iterate over all commits
    logger.info(
        "Found %s commit(s), from %s to %s",
        str(len(commits)),
        commits[0],
        commits[-1],
    )

    return commits
