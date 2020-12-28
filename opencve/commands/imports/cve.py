import gzip
import json
from io import BytesIO

import arrow
import requests

from opencve.commands import header, info, timed_operation
from opencve.commands.imports.cpe import get_slug
from opencve.extensions import db
from opencve.utils import convert_cpes, flatten_vendors, get_cwes
from opencve.models import get_uuid
from opencve.models.changes import Change
from opencve.models.cve import Cve
from opencve.models.tasks import Task

NVD_CVE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"


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

                # Create the CVEs mappings
                mappings["cves"].append(
                    dict(
                        id=cve_db_id,
                        cve_id=item["cve"]["CVE_data_meta"]["ID"],
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
