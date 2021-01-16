from opencve.checks import BaseCheck
from opencve.commands.utils import CveUtil
from opencve.extensions import db


class Cvss(BaseCheck):
    def execute(self):
        # Some CVE does not have CVSS, or they just have one version
        # Check the old values
        old = {}
        if self.cve_obj.cvss2:
            old["v2"] = self.cve_obj.cvss2
        if self.cve_obj.cvss3:
            old["v3"] = self.cve_obj.cvss3

        # Check the new values
        new = {}
        if "baseMetricV2" in self.cve_json["impact"]:
            new["v2"] = self.cve_json["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
        if "baseMetricV3" in self.cve_json["impact"]:
            new["v3"] = self.cve_json["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]

        # If at least one version has changed, update the CVE
        if old != new:
            self.cve_obj.cvss2 = new.get("v2")
            self.cve_obj.cvss3 = new.get("v3")
            db.session.commit()

            # Create the event with the CVSS changes
            event = CveUtil.create_event(
                self.cve_obj, self.cve_json, "cvss", {"old": old, "new": new}
            )
            return event

        return None
