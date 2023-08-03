import json

import more_itertools
from airflow.providers.postgres.hooks.postgres import PostgresHook
from airflow.providers.redis.hooks.redis import RedisHook
from nested_lookup import nested_lookup

PRODUCT_SEPARATOR = "$PRODUCT$"


def vendors_conf_to_dict(conf):
    """
    This function takes an object, extracts its CPE uris and transforms them into
    a dictionary representing the vendors with their associated products.
    """
    uris = nested_lookup("criteria", conf)

    # Create a list of tuple (vendor, product)
    cpes_t = list(set([tuple(uri.split(":")[3:5]) for uri in uris]))

    # Transform it into nested dictionnary
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


def decode_hmap(key):
    """
    Transform an encoded Redis hmap into a valid dictionary.

        Before: {b'uuid': b'["cisco", "microsoft"]'}
        After:  {'uuid': ['cisco', 'microsoft']}
    """
    hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    return {k.decode(): json.loads(v.decode()) for k, v in hook.hgetall(key).items()}


def merge_projects_changes(projects_subscriptions, vendors_changes):
    """
    This function takes 2 parameters:
        - a list of projects with their subscriptions
        - a list of vendors with their last changes
    It associates the projects with their changes according to the subscriptions.

    Example:
        >>> projects_subscriptions = {'projet1': ['foo', 'bar'], 'projet2': ['baz'], 'projet3': ['lorem', 'foo']}
        >>> vendors_changes = {'foo': ['change1', 'change2'], 'bar': ['change3'], 'oil': ['change1']}
        >>> merge_projects_changes(projects_subscriptions, vendors_changes)
        {'projet1': ['change2', 'change1', 'change3'], 'projet2': [], 'projet3': ['change2', 'change1']}
    """
    projects_changes = {}
    for project, subscriptions in projects_subscriptions.items():
        projects_changes[project] = set()
        for subscription in subscriptions:
            if subscription in vendors_changes.keys():
                projects_changes[project].update(vendors_changes[subscription])
        projects_changes[project] = list(projects_changes[project])

    return {k: v for k, v in projects_changes.items() if v}
