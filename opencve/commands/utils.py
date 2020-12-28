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
from opencve.utils import convert_cpes, flatten_vendors, get_cwes


class CveUtil(object):
    @classmethod
    def cve_has_changed(cls, cve_db, cve_json):
        return arrow.get(cve_json["lastModifiedDate"]) != cve_db.updated_at

    @classmethod
    def create_event(cls, cve_obj, cve_json, type, payload={}):
        event = Event(
            created_at=arrow.get(cve_json["lastModifiedDate"]).datetime,
            updated_at=arrow.get(cve_json["lastModifiedDate"]).datetime,
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
            created_at=arrow.get(cve_json["lastModifiedDate"]).datetime,
            updated_at=arrow.get(cve_json["lastModifiedDate"]).datetime,
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
        cvss2 = (
            cve_json["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
            if "baseMetricV2" in cve_json["impact"]
            else None
        )
        cvss3 = (
            cve_json["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
            if "baseMetricV3" in cve_json["impact"]
            else None
        )

        # Construct CWE and CPE lists
        cwes = get_cwes(
            cve_json["cve"]["problemtype"]["problemtype_data"][0]["description"]
        )
        cpes = convert_cpes(cve_json["configurations"])
        vendors = flatten_vendors(cpes)

        # Create the CVE
        cve = Cve(
            cve_id=cve_json["cve"]["CVE_data_meta"]["ID"],
            summary=cve_json["cve"]["description"]["description_data"][0]["value"],
            json=cve_json,
            vendors=vendors,
            cwes=cwes,
            cvss2=cvss2,
            cvss3=cvss3,
            created_at=arrow.get(cve_json["publishedDate"]).datetime,
            updated_at=arrow.get(cve_json["lastModifiedDate"]).datetime,
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
        vendors_products = convert_cpes(
            nested_lookup("cpe23Uri", cve_json["configurations"])
        )
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
