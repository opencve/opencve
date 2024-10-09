import time
from datetime import datetime

import arrow
import requests
from celery.utils.log import get_task_logger

from opencve.checks import BaseCheck
from opencve.commands.utils import CveUtil
from opencve.extensions import cel, db
from opencve.models.cve import Cve
from opencve.models.metas import Meta
from opencve.models.tasks import Task

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
logger = get_task_logger(__name__)


def get_last_cve():
    cve_id = Meta.query.filter_by(name="nvd_last_cve_id").first().value
    updated_at = arrow.get(
        Meta.query.filter_by(name="nvd_last_cve_updated_at").first().value
    )
    return cve_id, updated_at


def save_last_cve(cve_id, updated_at):
    meta_last_cve = Meta.query.filter_by(name="nvd_last_cve_id").first()
    meta_last_cve.value = cve_id
    meta_last_cve = Meta.query.filter_by(name="nvd_last_cve_updated_at").first()
    meta_last_cve.value = str(updated_at)
    db.session.commit()


def check_for_update(cve_json, task):
    cve_id = cve_json["id"]
    cve_obj = Cve.query.filter_by(cve_id=cve_id).first()
    events = []

    # A new CVE has been added
    if not cve_obj:
        cve_obj = CveUtil.create_cve(cve_json)
        logger.info("{} created (ID: {})".format(cve_id, cve_obj.id))
        events = [CveUtil.create_event(cve_obj, cve_json, "new_cve", {})]

    # Existing CVE has changed
    elif CveUtil.cve_has_changed(cve_obj, cve_json):
        logger.info("{} has changed, parsing it...".format(cve_obj.cve_id))

        events = []
        checks = BaseCheck.__subclasses__()

        # Loop on each kind of check
        for check in checks:
            c = check(cve_obj, cve_json)
            event = c.execute()

            if event:
                events.append(event)

        # Change the last updated date
        cve_obj.updated_at = arrow.get(cve_json["lastModified"]).datetime
        cve_obj.json = cve_json
        db.session.commit()

    # Create the change
    if events:
        CveUtil.create_change(cve_obj, cve_json, task, events)


@cel.task(name="HANDLE_EVENTS")
def handle_events():
    cel.app.app_context().push()

    # Retrieve the last CVE to start the synchronization
    last_cve_id, last_updated_at = get_last_cve()

    logger.info(f"Parsing last events since {last_cve_id} (at {last_updated_at})")
    start = last_updated_at.strftime("%Y-%m-%dT%H:%M:%S")
    end = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
    url_template = (
        NVD_API_URL
        + f"?lastModStartDate={start}Z&lastModEndDate={end}Z"
        + "&startIndex={idx}"
    )

    # Create the task containing the changes
    task = Task()
    db.session.add(task)

    # Iterate over all new CVEs
    start_index = 0
    total_results = 0
    while start_index <= total_results:
        url = url_template.format(idx=start_index)
        logger.info(f"Fetching {url}")
        resp = requests.get(url)

        # Continue if status != 200
        if not resp.ok:
            logger.info(
                f"Bad response: {resp.status_code}, sleeping before retrying..."
            )
            time.sleep(10)
            continue

        data = resp.json()
        total_results = data.get("totalResults")

        for vulnerability in data.get("vulnerabilities"):
            cve = vulnerability.get("cve")
            check_for_update(cve, task)

            # Store the last CVE info
            cve_last_modified = arrow.get(cve["lastModified"])
            if last_updated_at < cve_last_modified:
                last_cve_id = cve["id"]
                last_updated_at = cve_last_modified

        # NVD requirement is 2000 CVE per page and 6s between requests
        start_index += 2000
        time.sleep(6)

    # Save the last CVE information for the next handle_events tasks
    save_last_cve(last_cve_id, last_updated_at)
