import time

import arrow
import requests

from opencve.commands import info, timed_operation
from opencve.extensions import db
from opencve.utils import convert_cpes, flatten_vendors, weaknesses_to_flat
from opencve.models import get_uuid
from opencve.models.changes import Change
from opencve.models.cve import Cve
from opencve.models.tasks import Task
from opencve.models.products import Product
from opencve.models.vendors import Vendor
from opencve.models.metas import Meta


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def get_slug(vendor, product=None):
    slug = vendor
    if product:
        slug += "-{}".format(product)
    return slug


def run():
    """
    Import the CVE list.

    Important notice:
        This product uses data from the NVD API but is not endorsed or certified by the NVD.
    """
    task = Task()
    db.session.add(task)
    db.session.commit()
    task_id = task.id

    mappings = {"vendors": {}, "products": {}, "cves": [], "changes": []}
    url_template = NVD_API_URL + "?startIndex={idx}"

    start_index = 0
    total_results = 0

    while start_index <= total_results:
        url = url_template.format(idx=start_index)
        with timed_operation(f"Downloading {url}"):
            resp = requests.get(url)

            if not resp.ok:
                info(f"Bad response: {resp.status_code}, sleeping before retrying")
                time.sleep(10)
                continue

        with timed_operation("Creating model objects"):
            data = resp.json()
            total_results = data.get("totalResults")
            for vulnerability in data.get("vulnerabilities"):
                cve_db_id = get_uuid()

                cve_data = vulnerability.get("cve")
                cve_id = cve_data["id"]

                # Takes the CVSS scores
                if "cvssMetricV31" in cve_data["metrics"]:
                    cvss3 = cve_data.get("metrics")["cvssMetricV31"][0]["cvssData"][
                        "baseScore"
                    ]
                elif "cvssMetricV30" in cve_data["metrics"]:
                    cvss3 = cve_data.get("metrics")["cvssMetricV30"][0]["cvssData"][
                        "baseScore"
                    ]
                else:
                    cvss3 = None

                if "cvssMetricV2" in cve_data.get("metrics"):
                    cvss2 = cve_data.get("metrics")["cvssMetricV2"][0]["cvssData"][
                        "baseScore"
                    ]
                else:
                    cvss2 = None

                # Construct CWE and CPE lists
                cwes = weaknesses_to_flat(cve_data.get("weaknesses"))
                vendors_products = convert_cpes(cve_data.get("configurations", {}))
                vendors_flatten = flatten_vendors(vendors_products)

                # In case of multiple languages, keep the EN one
                descriptions = cve_data["descriptions"]
                if len(descriptions) > 1:
                    descriptions = [
                        d for d in descriptions if d["lang"] in ("en", "en-US")
                    ]
                summary = descriptions[0]["value"]

                # Create the CVEs mappings
                mappings["cves"].append(
                    dict(
                        id=cve_db_id,
                        cve_id=cve_id,
                        summary=summary,
                        json=cve_data,
                        vendors=vendors_flatten,
                        cwes=cwes,
                        cvss2=cvss2,
                        cvss3=cvss3,
                        created_at=arrow.get(cve_data["published"]).datetime,
                        updated_at=arrow.get(cve_data["lastModified"]).datetime,
                    )
                )

                # Create the vendors and their products
                for vendor, products in vendors_products.items():

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

        # NVD requirement is 2000 CVE per page
        start_index += 2000

        # Insert the objects in database
        if (start_index % 20_000 == 0) or (start_index >= total_results):
            with timed_operation("Inserting CVE"):
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
            mappings["cves"] = []
            mappings["changes"] = []

        # NVD requirement is 6s between requests
        if start_index <= total_results:
            info("Waiting 6 seconds")
            time.sleep(6)

    # Save the last CVE in database (will be reused in the handle_events task
    with timed_operation("Saving last CVE information"):
        last_cve = Cve.query.order_by(Cve.updated_at.desc()).first()
        db.session.add(Meta(name="nvd_last_cve_id", value=str(last_cve.cve_id)))
        db.session.add(
            Meta(name="nvd_last_cve_updated_at", value=str(last_cve.updated_at))
        )
        db.session.commit()

    # Insert the objects in database
    with timed_operation("Inserting Vendors and Products"):
        db.session.bulk_insert_mappings(Vendor, mappings["vendors"].values())
        db.session.bulk_insert_mappings(Product, mappings["products"].values())
        db.session.commit()
