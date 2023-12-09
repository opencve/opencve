import arrow
from nested_lookup import nested_lookup

from opencve.commands import info
from opencve.extensions import db
from opencve.models.changes import Change
from opencve.models.cve import Cve
from opencve.models.cwe import Cwe
from opencve.models.events import Event
from opencve.models.products import Product
from opencve.models.vendors import Vendor
from opencve.utils import convert_cpes, flatten_vendors, weaknesses_to_flat


class CveUtil(object):
    @classmethod
    def cve_has_changed(cls, cve_db, cve_json):
        return arrow.get(cve_json["lastModified"]) != cve_db.updated_at

    @classmethod
    def create_event(cls, cve_obj, cve_json, type, payload={}):
        event = Event(
            created_at=arrow.get(cve_json["lastModified"]).datetime,
            updated_at=arrow.get(cve_json["lastModified"]).datetime,
            cve=cve_obj,
            type=type,
            details=payload,
            review=False,
        )
        db.session.add(event)
        db.session.commit()

        info("Event {} created (ID: {})".format(type, event.id))
        return event

    @classmethod
    def create_change(cls, cve_obj, cve_json, task, events):
        change = Change(
            created_at=arrow.get(cve_json["lastModified"]).datetime,
            updated_at=arrow.get(cve_json["lastModified"]).datetime,
            cve=cve_obj,
            task=task,
            events=events,
            json=cve_json,
        )
        db.session.add(change)
        db.session.commit()

        info("Change created (ID: {})".format(change.id))
        return change

    @classmethod
    def create_cve(cls, cve_json):
        # Takes the CVSS scores
        if "cvssMetricV31" in cve_json["metrics"]:
            cvss3 = cve_json.get("metrics")["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV30" in cve_json["metrics"]:
            cvss3 = cve_json.get("metrics")["cvssMetricV30"][0]["cvssData"]["baseScore"]
        else:
            cvss3 = None

        if "cvssMetricV2" in cve_json.get("metrics"):
            cvss2 = cve_json.get("metrics")["cvssMetricV2"][0]["cvssData"]["baseScore"]
        else:
            cvss2 = None

        # Construct CWE and CPE lists
        cwes = weaknesses_to_flat(cve_json.get("weaknesses"))
        vendors_products = convert_cpes(cve_json.get("configurations", {}))
        vendors_flatten = flatten_vendors(vendors_products)

        # In case of multiple languages, keep the EN one
        descriptions = cve_json["descriptions"]
        if len(descriptions) > 1:
            descriptions = [d for d in descriptions if d["lang"] in ("en", "en-US")]
        summary = descriptions[0]["value"]

        # Create the CVE
        cve = Cve(
            cve_id=cve_json.get("id"),
            summary=summary,
            json=cve_json,
            vendors=vendors_flatten,
            cwes=cwes,
            cvss2=cvss2,
            cvss3=cvss3,
            created_at=arrow.get(cve_json["published"]).datetime,
            updated_at=arrow.get(cve_json["lastModified"]).datetime,
        )
        db.session.add(cve)
        db.session.commit()

        # Add the CWE that not exists yet in database
        for cwe in cwes:
            cwe_obj = Cwe.query.filter_by(cwe_id=cwe).first()
            if not cwe_obj:
                info(
                    f"{cwe} detected in {cve.cve_id} but not existing in database, adding it..."
                )
                cwe_obj = Cwe(cwe_id=cwe)
                db.session.add(cwe_obj)
                db.session.commit()

        # Add the CPEs
        for vendor, products in vendors_products.items():
            v_obj = Vendor.query.filter_by(name=vendor).first()

            # Create the vendor
            if not v_obj:
                v_obj = Vendor(name=vendor)
                db.session.add(v_obj)
                db.session.commit()

            # Create the products
            for product in products:
                p_obj = Product.query.filter_by(name=product, vendor=v_obj).first()
                if not p_obj:
                    p_obj = Product(name=product, vendor=v_obj)
                    db.session.add(p_obj)
                    db.session.commit()

        return cve
