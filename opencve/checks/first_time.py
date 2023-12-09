from opencve.checks import BaseCheck
from opencve.commands.utils import CveUtil
from opencve.utils import vendors_conf_to_flat


class FirstTime(BaseCheck):
    def execute(self):
        old_confs = vendors_conf_to_flat(self.cve_obj.json.get("configurations", []))
        new_confs = vendors_conf_to_flat(self.cve_json.get("configurations", []))

        payload = list(set(new_confs) - set(old_confs))
        if payload:
            event = CveUtil.create_event(
                self.cve_obj, self.cve_json, "first_time", payload
            )
            return event

        return None
