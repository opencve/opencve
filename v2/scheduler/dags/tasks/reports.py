import json
import logging

import arrow
from airflow.decorators import task
from airflow.providers.postgres.hooks.postgres import PostgresHook
from airflow.providers.redis.hooks.redis import RedisHook
from psycopg2.extras import Json

from constants import SQL_VENDORS_PER_CHANGE, SQL_REPORTS
from utils import decode_hmap, merge_projects_changes

logger = logging.getLogger(__name__)


@task
def get_changes():
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    postgres_hook = PostgresHook(postgres_conn_id="opencve_postgres")

    # Get the list of the changes ids saved in a previous task
    changes_ids = tuple([id.decode() for id in redis_hook.smembers("changes_ids")])
    logger.info(f"Got {len(changes_ids)} changes to analyze")
    if not changes_ids:
        return

    # Get the associated vendors for each change
    logger.info("Get the associated vendors for each change")
    changes = postgres_hook.get_records(
        sql=SQL_VENDORS_PER_CHANGE, parameters={"changes": changes_ids}
    )

    # Sort the changes per vendors
    logger.info(f"Sorting {len(changes_ids)} changes per vendor...")
    vendors_changes = {}
    for change_id, vendors in changes:
        for vendor in vendors:
            if vendor not in vendors_changes:
                vendors_changes[vendor] = []
            vendors_changes[vendor].append(change_id)

    # Encode the dictionary to save it in redis
    vendors_changes = {k: json.dumps(v) for k, v in vendors_changes.items()}

    # Save the result to reuse it in a next task
    logger.info(
        f"Saving {len(vendors_changes)} vendors and their changes in redis (key: vendors_changes)"
    )

    redis_hook.delete("vendors_changes")
    redis_hook.hset("vendors_changes", mapping=vendors_changes)

    # Clean the existing `changes_ids` redis key
    redis_hook.delete("changes_ids")


@task
def get_subscriptions():
    logger.info("Listing projects and their subscriptions")

    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    postgres_hook = PostgresHook(postgres_conn_id="opencve_postgres")

    # Retrieve the list of projects
    projects = postgres_hook.get_records(
        sql="SELECT id, subscriptions FROM opencve_projects"
    )
    logger.info(f"Got {len(projects)} rows from database")

    # Remove the project without subscriptions
    projects_subscriptions = {}
    for project in projects:
        vendors = project[1]["vendors"] + project[1]["products"]
        if vendors:
            projects_subscriptions[project[0]] = json.dumps(vendors)

    # Save this result in redis to reuse it in the next task
    logger.info(
        f"Saving {len(projects_subscriptions)} projects with subscriptions in redis (key: projects_subscriptions)"
    )
    redis_hook.delete("projects_subscriptions")
    redis_hook.hset("projects_subscriptions", mapping=projects_subscriptions)


@task
def populate_reports(execution_date=None):
    day = arrow.get(execution_date).floor("day").to("utc").datetime.isoformat()

    # Retrieve the projects and their subscriptions
    projects_subscriptions = decode_hmap("projects_subscriptions")
    logger.info(f"Got {len(projects_subscriptions)} projects and their subscriptions")
    if not projects_subscriptions:
        return

    # Retrieve the changes and their vendors
    vendors_changes = decode_hmap("vendors_changes")
    logger.info(f"Got {len(vendors_changes)} changes and their vendors")
    if not vendors_changes:
        return

    # Associate each project to its changes
    projects_changes = merge_projects_changes(projects_subscriptions, vendors_changes)
    logger.info(f"Got {len(projects_changes)} projects with changes")
    if not projects_changes:
        return

    # Create the reports for each project
    hook = PostgresHook(postgres_conn_id="opencve_postgres")
    for project, changes in projects_changes.items():
        hook.run(
            sql=SQL_REPORTS,
            parameters={
                "created": day,  # TODO: je me demande si le day doit pas être lié à la date de change
                "project": project,
                "details": Json({"cves": [], "vendors": []}),
                "changes": Json(changes),
            },
        )
