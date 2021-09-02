import gzip
import json
import re
from io import BytesIO

from urllib.parse import urlparse
from datetime import datetime
import arrow
import feedparser
import hashlib
import os
import requests
import tempfile
from celery.utils.log import get_task_logger

from opencve.checks import BaseCheck
from opencve.commands.utils import CveUtil
from opencve.extensions import cel, db
from opencve.models.cve import Cve
from opencve.models.metas import Meta
from opencve.models.tasks import Task

NVD_MODIFIED_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz"
NVD_MODIFIED_META_URL = (
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.meta"
)
logger = get_task_logger(__name__)

def read_last_rss():
    """
    Read Json file on tmp directory to get last RSS update
    """
    fstate = {}
    file_json = tempfile.gettempdir() + "/rss_exploited_state.json"
    if not os.path.isfile(file_json):
        return fstate
    try:
        with open(file_json) as json_file:
            fstate = json.load(json_file)
        return fstate
    except Exception as err:
        logger.info("Error to read: {} -> {}.".format(file_json, err))
        return fstate

def write_last_rss(fstate):
    """
    Write Json file on tmp directory to put last RSS update
    """
    file_json = tempfile.gettempdir() + "/rss_exploited_state.json"
    try:
        with open(file_json, 'w') as json_file:
            json.dump(fstate, json_file, indent=4, sort_keys=True)
    except Exception as err:
        logger.info("Error to write: {} -> {}.".format(file_json, err))

def get_exploited_cve_from_rss():
    """
    GET RSS Flux to find CVE numbers exploited in wild
    """
    cve_exploited=[]

    if cel.app.config["EXPLOITED_LOCAL"]:
        cve_exploited = \
            cel.app.config["EXPLOITED_LOCAL"].upper().replace(" ", "").split(',')

    if not cel.app.config["RSS_EXPLOITED"]:
        return cve_exploited

    fstate=read_last_rss()
    if not fstate:
        fstate = { "last_time": "", "hash_rss": [], "exploited_cve": [] }
    else:
        if "exploited_cve" in fstate and fstate["exploited_cve"]:
            cve_exploited = list(set(cve_exploited + fstate["exploited_cve"]))
        if "last_time" in fstate:
            dlast = datetime.strptime(fstate["last_time"], "%Y-%m-%dT%H:%M:%S")
            if int((datetime.now()-dlast).total_seconds()) < int(cel.app.config["UPDATE_RSS"]):
                logger.info("Dont check update RSS (wait {}seconds between 2 checks).".format(cel.app.config["UPDATE_RSS"]))
                return cve_exploited
    fstate["last_time"] = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')

    for url in cel.app.config["RSS_EXPLOITED"].replace(" ", "").split(','):
        limit_domain = urlparse(url).netloc
        result = requests.get(url, allow_redirects=False)
        hash_rss = hashlib.sha256(result.text.encode()).hexdigest()
        if hash_rss not in fstate["hash_rss"]:
            logger.info("{} update RSS.".format(url))
            fstate["hash_rss"].append(hash_rss)
            feed = feedparser.parse(result.text)
            for post in feed.entries:
                todom = urlparse(post.link).netloc
                if todom == limit_domain:
                    result = requests.get(post.link, allow_redirects=True)
                    found=re.findall(r'CVE\-[0-9]{4}\-[0-9]+',result.text)
                    cve_exploited=list(set(cve_exploited + found))

    fstate["exploited_cve"] = cve_exploited
    write_last_rss(fstate)
    return cve_exploited

def update_exploited_cve_from_rss(cve_exploited, task):
    """
    Check if CVE exist contains CVE exploited
    """
    events = []
    for cve_id in cve_exploited:
        cve_obj = Cve.query.filter_by(cve_id=cve_id).first()
        if not cve_obj:
            logger.info("CVE exploited: {} dont exist in DB openCVE.".format(cve_id))
            continue
        if cve_obj.exploited == True:
            continue
        cve_obj.exploited = True
        db.session.commit()
        event = CveUtil.create_event(cve_obj, cve_obj.json, "exploited", {"old": False, "new": True})
        if event:
            events.append(event)

    # Create the change
    if events:
        CveUtil.create_change(cve_obj, cve_obj.json, task, events)

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
    logger.info("DB is up to date.")
    return last_nvd256, None


def download_modified_items():
    logger.info("Downloading {}...".format(NVD_MODIFIED_URL))
    resp = requests.get(NVD_MODIFIED_URL).content
    raw = gzip.GzipFile(fileobj=BytesIO(resp)).read()
    items = json.loads(raw.decode("utf-8"))["CVE_Items"]
    return items


def check_for_update(cve_json, task, exploit_db = []):
    cve_id = cve_json["cve"]["CVE_data_meta"]["ID"]
    cve_obj = Cve.query.filter_by(cve_id=cve_id).first()
    events = []

    # A new CVE has been added
    if not cve_obj:
        cve_obj = CveUtil.create_cve(cve_json, exploit_db)
        logger.info("{} created (ID: {})".format(cve_id, cve_obj.id))
        events = [CveUtil.create_event(cve_obj, cve_json, "new_cve", {})]

    # Existing CVE has changed
    elif CveUtil.cve_has_changed(cve_obj, cve_json):
        logger.info("{} has changed, parsing it...".format(cve_obj.cve_id))

        events = []
        checks = BaseCheck.__subclasses__()

        # Loop on each kind of check
        old_exploit = cve_obj.exploit
        for check in checks:
            c = check(cve_obj, cve_json)
            event = c.execute()

            if event:
                events.append(event)

        # Check Exploit public
        if cve_obj.exploit != old_exploit:
            event = CveUtil.create_event(cve_obj, cve_json, "exploit", {"old": False, "new": True})
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

    #check cve exploited
    logger.info("Checking for CVE exploited...")
    exploit_db = get_exploited_cve_from_rss()

    logger.info("Checking for new events...")
    current_sum, new_sum = has_changed()
    if not new_sum:
        task = Task()
        db.session.add(task)
        update_exploited_cve_from_rss(exploit_db, task)
        db.session.commit()
        return

    # Retrieve the list of modified CVEs
    logger.info("Download modified CVEs...")
    items = download_modified_items()

    # Create the task containing the changes
    task = Task()
    db.session.add(task)

    update_exploited_cve_from_rss(exploit_db, task)

    logger.info("Checking {} CVEs...".format(len(items)))
    for item in items:
        check_for_update(item, task, exploit_db)

    logger.info("CVEs checked, updating meta hash...")
    current_sum.value = new_sum
    db.session.commit()
    logger.info("Done, new meta is {}.".format(new_sum))
