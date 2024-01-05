import arrow
import more_itertools
from airflow.providers.postgres.hooks.postgres import PostgresHook
from nested_lookup import nested_lookup
from psycopg2.extras import Json

from includes.constants import PRODUCT_SEPARATOR


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
    """
    This function parses the CVE defined in KB file and uses a pre-defined
    priority order to populate the CVE fields based on MITRE and NVD data.

    Here is a summary of each field:
    - `created`: most recent date between MITRE & NVD fields
    - `updated`: most recent date between MITRE & NVD fields
    - `summary`: first the Mitre summary, then the Nvd one
    - `vendors`: from the NVD only
    - `cvss`: from the NVD only
    - `cwes`: from the NVD only
    """
    payload = {
        "summary": None,
        "created": "1970-01-01T00:00:00.000000+00:00",
        "updated": "1970-01-01T00:00:00.000000+00:00",
        "vendors": Json([]),
        "cvss": Json({}),
        "cwes": Json([]),
    }

    if "mitre" in kb_data:
        payload.update({
            "summary": kb_data["mitre"]["summary"],
            "created": kb_data["mitre"]["created"],
            "updated": kb_data["mitre"]["updated"],
        })

    if "nvd" in kb_data:
        # Take the most recent created date
        if arrow.get(payload["created"]) < arrow.get(kb_data["nvd"]["created"]):
            payload["created"] = kb_data["nvd"]["created"]

        # Take the most recent updated date
        if arrow.get(payload["updated"]) < arrow.get(kb_data["nvd"]["updated"]):
            payload["updated"] = kb_data["nvd"]["updated"]

        # Use the Mitre summary, then the NVD one
        # TODO: add the nvd summary in internal scheduler
        if not payload["summary"]:
            #payload["summary"] = kb_data["nvd"]["summary"]
            payload["summary"] = "here will be the nvd summary"

        # Use the NVD only fields
        payload.update({
            "vendors": Json(kb_data["nvd"]["vendors"]),
            "cvss": Json(kb_data["nvd"]["cvss"]),
            "cwes": Json(kb_data["nvd"]["cwes"])
        })

    return payload
