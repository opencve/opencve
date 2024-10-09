from opencve.checks import BaseCheck
from opencve.commands import info
from opencve.commands.utils import CveUtil
from opencve.extensions import db
from opencve.models.cwe import Cwe
from opencve.utils import weaknesses_to_flat


class Cwes(BaseCheck):
    def execute(self):

        new_weaknesses = weaknesses_to_flat(self.cve_json.get("weaknesses"))
        old_weaknesses = weaknesses_to_flat(self.cve_obj.json.get("weaknesses"))

        payload = {
            "added": list(set(new_weaknesses) - set(old_weaknesses)),
            "removed": list(set(old_weaknesses) - set(new_weaknesses)),
        }

        # It's possible that a CVE links a CWE not yet defined in database.
        # In this case we'll save it in the `cwes` table and a periodic task
        # will populate later its name and description using the MITRE file.
        for cwe_id in payload["added"]:
            cwe = Cwe.query.filter_by(cwe_id=cwe_id).first()

            if not cwe:
                info(
                    f"{cwe_id} detected in {self.cve_obj.cve_id} but not existing in database, adding it..."
                )
                cwe = Cwe(cwe_id=cwe_id)
                db.session.add(cwe)
                db.session.commit()

        # If the list of CWE changed
        if payload["added"] or payload["removed"]:

            # Save the new list
            self.cve_obj.cwes = new_weaknesses
            db.session.commit()

            # Create the event
            event = CveUtil.create_event(self.cve_obj, self.cve_json, "cwes", payload)
            return event

        return None
