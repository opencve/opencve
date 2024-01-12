import pathlib
from logging import Logger
from typing import List

import more_itertools
from nested_lookup import nested_lookup
from psycopg2.extras import Json
from git.repo import Repo
from git.objects.commit import Commit
from airflow.providers.postgres.hooks.postgres import PostgresHook
from airflow.exceptions import AirflowException
from pendulum.datetime import DateTime

from includes.constants import PRODUCT_SEPARATOR, KB_LOCAL_REPO


def vendors_conf_to_dict(conf):
    """
    This function takes an object, extracts its CPE uris and transforms them into
    a dictionary representing the vendors with their associated products.
    """
    uris = nested_lookup("criteria", conf)

    # Create a list of tuple (vendor, product)
    cpes_t = list(set([tuple(uri.split(":")[3:5]) for uri in uris]))

    # Transform it into nested dictionary
    cpes = {}
    for vendor, product in cpes_t:
        if vendor not in cpes:
            cpes[vendor] = []
        cpes[vendor].append(product)

    return cpes


def vendors_dict_to_flat(vendors):
    """
    Takes a list of nested vendors and products and flat them.
    """
    data = []
    for vendor, products in vendors.items():
        data.append(vendor)
        for product in products:
            data.append(f"{vendor}{PRODUCT_SEPARATOR}{product}")
    return data


def vendors_conf_to_flat(conf=None):
    """
    Takes a list of CPEs configuration and returns it in a flat
    array with a vendor/product separator in each item.
    """
    if not conf:
        return []
    return vendors_dict_to_flat(vendors_conf_to_dict(conf))


def weaknesses_to_flat(weaknesses=None):
    return nested_lookup("value", weaknesses)


def get_chunks(projects, max_map_length):
    """
    Distribute the projects into X chunks.

    Examples:
      >>> get_chunks(["a", "b", "c", "d"], 5)
      >>> [["a"], ["b"], ["c"], ["d"]]
      >>> get_chunks(["a", "b", "c", "d"], 3)
      >>> [["a", "b"], ["c"], ["d"]]
    """
    if len(projects) <= max_map_length:
        return [[p] for p in projects]

    projects_lists = []
    for chunk in more_itertools.divide(max_map_length, projects):
        projects_lists.append(list(chunk))

    return projects_lists


def run_sql(query, parameters):
    """
    Execute a SQL query with parameters.
    """
    hook = PostgresHook(postgres_conn_id="opencve_postgres")
    hook.run(sql=query, parameters=parameters)


def get_vendor_changes(records):
    """
    This function takes a list of changes and
    associates them with their vendors.

    Example:
        >>> records = [
            ('de7989bd-68c1-45b2-9fab-273df1bb53ef', ['foo', 'bar']),
            ('2d8a382a-d43f-4601-b4b2-d55b49013b8b', ['bar'])
        ]
        >>> get_vendor_changes(records)
        {
            'foo': ['de7989bd-68c1-45b2-9fab-273df1bb53ef'],
            'bar': ['de7989bd-68c1-45b2-9fab-273df1bb53ef', '2d8a382a-d43f-4601-b4b2-d55b49013b8b']
        }
    """
    vendors_changes = {}

    for change_id, vendors in records:
        for vendor in vendors:
            if vendor not in vendors_changes:
                vendors_changes[vendor] = []
            vendors_changes[vendor].append(change_id)

    return vendors_changes


def get_project_subscriptions(records):
    """
    This function returns a list of projects with their associated
    vendors and products.

    Example:
        >>> records = [(
            '8d5d399c-1f3c-4e83-91ba-6f7cf057b70b', {'vendors': ['foo', 'bar'], 'products': ['vendor$PRODUCT$product']}
        )]
        >>> get_project_subscriptions(records)
        >>> {'8d5d399c-1f3c-4e83-91ba-6f7cf057b70b': ['foo', 'bar', 'vendor$PRODUCT$product']}
    """
    projects_subscriptions = {}
    for project in records:
        vendors = project[1]["vendors"] + project[1]["products"]
        if vendors:
            projects_subscriptions[project[0]] = vendors
    return projects_subscriptions


def get_reports(changes, subscriptions):
    """
    This associates the project subscriptions with their changes.

    Example:
        >>> changes = {
            'foo': ['de7989bd-68c1-45b2-9fab-273df1bb53ef'],
            'bar': ['de7989bd-68c1-45b2-9fab-273df1bb53ef', '2d8a382a-d43f-4601-b4b2-d55b49013b8b']
        }
        >>> subscriptions = {
            '8d5d399c-1f3c-4e83-91ba-6f7cf057b70b': ['foo', 'bar', 'vendor$PRODUCT$product']
        }
        >>> get_reports(subscriptions, changes)
        {
            "8d5d399c-1f3c-4e83-91ba-6f7cf057b70b": [
                "de7989bd-68c1-45b2-9fab-273df1bb53ef",
                "2d8a382a-d43f-4601-b4b2-d55b49013b8b"
            ]
        }
    """
    projects_changes = {}
    for project, subscriptions in subscriptions.items():
        projects_changes[project] = set()
        for subscription in subscriptions:
            if subscription in changes.keys():
                projects_changes[project].update(changes[subscription])
        projects_changes[project] = list(projects_changes[project])

    return {k: v for k, v in projects_changes.items() if v}


def get_project_notifications(records):
    """
    TO COMPLETE
    """
    projects_notifications = {}
    for notification in records:
        project_id, notif_type, notif_conf = notification
        if project_id not in projects_notifications:
            projects_notifications[project_id] = []
        projects_notifications[project_id].append({
            "type": notif_type,
            "conf": notif_conf
        })
    return projects_notifications


def format_procedure_payload(data, raw_fields, json_fields):
    payload = {}
    for k, v in data.items():
        if k in raw_fields:
            payload[k] = v
        if k in json_fields:
            payload[k] = Json(v)
    return payload


def get_start_end_dates(context):
    start = context.get("data_interval_start")
    end = context.get("data_interval_end").subtract(seconds=1)
    return start, end


def format_cve_payload(kb_data):
    data = kb_data["opencve"]
    payload = {
        "cve": data["cve"],
        "description": data["description"],
        "title": data["title"],
        "created": data["created"],
        "updated": data["updated"],
        "vendors": Json(data["vendors"]),
        "metrics": Json(data["metrics"]),
        "weaknesses": Json(data["weaknesses"]),
    }
    return payload


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
        logger.info("No commit found, skip the task")
        return []

    # Iterate over all commits
    logger.info(
        "Found %s commit(s), from %s to %s",
        str(len(commits)),
        commits[0],
        commits[-1],
    )

    return commits
