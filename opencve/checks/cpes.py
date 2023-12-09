from nested_lookup import nested_lookup

from opencve.checks import BaseCheck
from opencve.commands.utils import CveUtil
from opencve.extensions import db
from opencve.models.products import Product
from opencve.models.vendors import Vendor
from opencve.utils import convert_cpes, flatten_vendors


class Cpes(BaseCheck):
    def execute(self):
        old_cpes = nested_lookup("criteria", self.cve_obj.json.get("configurations"))
        new_cpes = nested_lookup("criteria", self.cve_json.get("configurations"))

        payload = {
            "added": list(set(new_cpes) - set(old_cpes)),
            "removed": list(set(old_cpes) - set(new_cpes)),
        }

        # The CPEs list has been modified
        if payload["added"] or payload["removed"]:

            # Change the CVE's vendors attribute
            vendors_products = convert_cpes(self.cve_json.get("configurations", {}))
            self.cve_obj.vendors = flatten_vendors(vendors_products)
            db.session.commit()

            for vendor, products in vendors_products.items():
                v_obj = Vendor.query.filter_by(name=vendor).first()

                # Create the vendor and associate it to the CVE
                if not v_obj:
                    v_obj = Vendor(name=vendor)
                    db.session.add(v_obj)
                    db.session.commit()

                # Do the same for its products
                for product in products:
                    p_obj = Product.query.filter_by(name=product, vendor=v_obj).first()
                    if not p_obj:
                        p_obj = Product(name=product, vendor=v_obj)
                        db.session.add(p_obj)
                        db.session.commit()

            # Create the event
            event = CveUtil.create_event(self.cve_obj, self.cve_json, "cpes", payload)
            return event

        return None
