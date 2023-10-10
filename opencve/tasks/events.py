import gzip
import csv
import json
import re
from io import BytesIO

import arrow
import requests
from celery.utils.log import get_task_logger

from opencve.checks import BaseCheck
from opencve.commands.utils import CveUtil
from opencve.extensions import cel, db
from opencve.models import get_uuid
from opencve.models.cve import Cve
from opencve.models.epss import Epss
from opencve.models.metas import Meta
from opencve.models.tasks import Task

NVD_MODIFIED_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz"
NVD_MODIFIED_META_URL = (
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.meta"
)
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
logger = get_task_logger(__name__)


def has_changed():
    logger.info("Downloading {}...".format(NVD_MODIFIED_META_URL))
    resp = requests.get(NVD_MODIFIED_META_URL)
    buf = BytesIO(resp.content).read().decode("utf-8")

    matches = re.match(r".*sha256:(\w{64}).*", buf, re.DOTALL)
    nvd_sha256 = matches.group(1)
    last_nvd256 = Meta.query.filter_by(name="nvd_last_sha256").first()

    if nvd_sha256 != last_nvd256.value:
        logger.info(
            "Found different hashes (old:{}, new:{}).".format(
                last_nvd256.value, nvd_sha256
            )
        )
        return last_nvd256, nvd_sha256
    else:
        logger.info("DB is up to date.")
        return last_nvd256, None


def download_modified_items():
    logger.info("Downloading {}...".format(NVD_MODIFIED_URL))
    resp = requests.get(NVD_MODIFIED_URL).content
    raw = gzip.GzipFile(fileobj=BytesIO(resp)).read()
    items = json.loads(raw.decode("utf-8"))["CVE_Items"]
    return items


def check_for_update(cve_json, task):
    cve_id = cve_json["cve"]["CVE_data_meta"]["ID"]
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
        cve_obj.updated_at = arrow.get(cve_json["lastModifiedDate"]).datetime
        cve_obj.json = cve_json
        db.session.commit()

    # Create the change
    if events:
        CveUtil.create_change(cve_obj, cve_json, task, events)


@cel.task(name="HANDLE_EVENTS")
def handle_events():
    cel.app.app_context().push()

    logger.info("Checking for new events...")
    current_sum, new_sum = has_changed()
    if new_sum:
        # Retrieve the list of modified CVEs
        logger.info("Download modified CVEs...")
        items = download_modified_items()

        # Create the task containing the changes
        task = Task()
        db.session.add(task)

        logger.info("Checking {} CVEs...".format(len(items)))
        for item in items:
            check_for_update(item, task)

        logger.info("CVEs checked, updating meta hash...")
        current_sum.value = new_sum
        db.session.commit()
        logger.info("Done, new meta is {}.".format(new_sum))

    # Handle EPSS updates
    logger.info("Checking for EPSS updates...")
    updated_epss_scores = download_and_check_epss_updates()
    if updated_epss_scores:
        task_epss = Task()
        db.session.add(task_epss)

        logger.info("Updating {} EPSS scores...".format(len(updated_epss_scores)))
        for score in updated_epss_scores:
            # score["task_id"] = task_epss.id
            update_epss_score(score)

        db.session.commit()
        logger.info("EPSS scores updated.")


def download_and_check_epss_updates():
    # Download the EPSS data
    # For simplicity, using the same approach as your import script
    resp = requests.get(EPSS_URL).content
    raw = gzip.GzipFile(fileobj=BytesIO(resp)).read()
    csv_content = csv.reader(raw.decode('utf-8').splitlines())

    # Skip headers
    next(csv_content)
    next(csv_content)

    updated_scores = []
    for row in csv_content:
        cve_id, epss_score, percentile = row
        epss_score = float(epss_score)
        percentile = float(percentile)

        # Fetch the UUID of the CVE using its cve_id
        cve_uuid = Cve.query.filter_by(cve_id=cve_id).first().id

        existing_epss = Epss.query.filter_by(cve_id=cve_id).first()
        if not existing_epss or existing_epss.score != epss_score:
            updated_scores.append(
                dict(
                    cve_id=cve_id,
                    cve_uuid=cve_uuid,
                    score=epss_score,
                    percentile=percentile,
                )
            )
    return updated_scores


def update_epss_score(score):
    existing_epss = Epss.query.filter_by(cve_id=score['cve_id']).first()
    if existing_epss:
        existing_epss.score = score['score']
        existing_epss.percentile = score['percentile']
    else:
        epss_obj = Epss(id=get_uuid(), **score)
        db.session.add(epss_obj)
