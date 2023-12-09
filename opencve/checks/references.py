import warnings

from opencve.checks import BaseCheck
from opencve.commands.utils import CveUtil

# Disable useless warnings in deepdiff
with warnings.catch_warnings():
    from deepdiff import DeepDiff


class References(BaseCheck):
    def execute(self):
        payload = {"changed": [], "added": [], "removed": []}

        old_refs = {ref["url"]: ref for ref in self.cve_obj.json.get("references")}
        new_refs = {ref["url"]: ref for ref in self.cve_json.get("references")}

        for new_url, new_ref in new_refs.items():
            # New reference
            if new_url not in old_refs.keys():
                payload["added"].append(new_ref)
                continue

            # Changed reference
            if new_ref != old_refs[new_url]:
                payload["changed"].append({"old": old_refs[new_url], "new": new_ref})

        for old_url, old_ref in old_refs.items():
            # Removed reference
            if old_url not in new_refs.keys():
                payload["removed"].append(old_ref)

        # Create the event with the references changes
        if payload["changed"] or payload["added"] or payload["removed"]:
            event = CveUtil.create_event(
                self.cve_obj, self.cve_json, "references", payload
            )
            return event

        return None
