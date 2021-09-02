import gzip
import json
import re
from io import BytesIO

from urllib.parse import urlparse

import arrow
import feedparser
import hashlib
import requests

from opencve.commands import header, info, timed_operation
from opencve.commands.imports.cpe import get_slug
from opencve.extensions import cel, db
from opencve.utils import convert_cpes, flatten_vendors, get_cwes
from opencve.models import get_uuid
from opencve.models.changes import Change
from opencve.models.cve import Cve
from opencve.models.tasks import Task

NVD_CVE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"

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

    for url in cel.app.config["RSS_EXPLOITED"].replace(" ", "").split(','):
        limit_domain = urlparse(url).netloc
        result = requests.get(url, allow_redirects=False)
        hash_rss = hashlib.sha256(result.text.encode()).hexdigest()
        if hash_rss not in cel.app.config["HASH_RSS"]:
            cel.app.config["HASH_RSS"].append(hash_rss)
            feed = feedparser.parse(result.text)
            for post in feed.entries:
                todom = urlparse(post.link).netloc
                if todom == limit_domain:
                    result = requests.get(post.link, allow_redirects=True)
                    found=re.findall(r'CVE\-[0-9]{4}\-[0-9]+',result.text)
                    cve_exploited=list(set(cve_exploited + found))

    return cve_exploited

def run():
    """
    Import the CVE list.
    """
    mappings = {"vendors": {}, "products": {}}

    from opencve.commands.imports import CURRENT_YEAR, CVE_FIRST_YEAR

    # Create the initial task
    task = Task()
    db.session.add(task)
    db.session.commit()
    task_id = task.id
    exploit_db = get_exploited_cve_from_rss()
    print("CVE exploited list: "+str(exploit_db))

    for year in range(CVE_FIRST_YEAR, CURRENT_YEAR + 1):
        header("Importing CVE for {}".format(year))
        mappings.update({"cves": [], "changes": []})

        # Download the file
        url = NVD_CVE_URL.format(year=year)
        with timed_operation("Downloading {}...".format(url)):
            resp = requests.get(url).content

        # Parse the XML elements
        with timed_operation("Parsing JSON elements..."):
            raw = gzip.GzipFile(fileobj=BytesIO(resp)).read()
            items = json.loads(raw.decode("utf-8"))["CVE_Items"]

        with timed_operation("Creating model objects..."):

            for item in items:
                cve_db_id = get_uuid()
                summary = item["cve"]["description"]["description_data"][0]["value"]
                cvss2 = (
                    item["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
                    if "baseMetricV2" in item["impact"]
                    else None
                )
                cvss3 = (
                    item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
                    if "baseMetricV3" in item["impact"]
                    else None
                )

                # Construct CWE and CPE lists
                cwes = get_cwes(
                    item["cve"]["problemtype"]["problemtype_data"][0]["description"]
                )
                cpes = convert_cpes(item["configurations"])
                vendors = flatten_vendors(cpes)

                # Check Exploit
                exploit_find = False
                if ( (cel.app.config["EXPLOIT_LINK"] or cel.app.config["EXPLOIT_TAG"])
                    and "reference_data" in item["cve"]["references"]):
                    for refs_cve in item["cve"]["references"]["reference_data"]:
                        if (
                            cel.app.config["EXPLOIT_TAG_NIST"]
                            and "tags" in refs_cve
                            and cel.app.config["EXPLOIT_TAG_NIST"] in refs_cve["tags"]):
                            exploit_find = True
                            break
                        if (
                            cel.app.config["EXPLOIT_LINK"]
                            and "url" in refs_cve):
                            for links_refs in cel.app.config["EXPLOIT_LINK"].split(','):
                                if links_refs in refs_cve["url"].lower():
                                    exploit_find = True
                                    break
                            if exploit_find:
                                break

                # Check if exploited from flux rss and local config
                exploited = False
                if item["cve"]["CVE_data_meta"]["ID"] in exploit_db:
                    exploited = True

                # Create the CVEs mappings
                mappings["cves"].append(
                    dict(
                        id=cve_db_id,
                        cve_id=item["cve"]["CVE_data_meta"]["ID"],
                        exploit=exploit_find,
                        exploited=exploited,
                        summary=summary,
                        json=item,
                        vendors=vendors,
                        cwes=cwes,
                        cvss2=cvss2,
                        cvss3=cvss3,
                        created_at=arrow.get(item["publishedDate"]).datetime,
                        updated_at=arrow.get(item["lastModifiedDate"]).datetime,
                    )
                )

                # Create the vendors and their products
                for vendor, products in cpes.items():

                    # Create the vendor
                    if vendor not in mappings["vendors"].keys():
                        mappings["vendors"][vendor] = dict(id=get_uuid(), name=vendor)

                    for product in products:
                        if get_slug(vendor, product) not in mappings["products"].keys():
                            mappings["products"][get_slug(vendor, product)] = dict(
                                id=get_uuid(),
                                name=product,
                                vendor_id=mappings["vendors"][vendor]["id"],
                            )

        # Insert the objects in database
        with timed_operation("Inserting CVE..."):
            db.session.bulk_insert_mappings(Cve, mappings["cves"])
            db.session.commit()

            # Create the changes based on CVEs data
            for cve in mappings["cves"]:
                mappings["changes"].append(
                    dict(
                        id=get_uuid(),
                        created_at=cve["created_at"],
                        updated_at=cve["updated_at"],
                        json=cve["json"],
                        cve_id=cve["id"],
                        task_id=task_id,
                    )
                )
            db.session.bulk_insert_mappings(Change, mappings["changes"])
            db.session.commit()

        info("{} CVE imported.".format(len(mappings["cves"])))

        # Free the memory after each processed year
        del mappings["cves"]
        del mappings["changes"]

    return mappings
