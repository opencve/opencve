import warnings

from opencve.checks import BaseCheck
from opencve.commands.utils import CveUtil

# Disable useless warnings in deepdiff
with warnings.catch_warnings():
    from deepdiff import DeepDiff


class References(BaseCheck):
    def execute(self):
        payload = {"changed": [], "added": [], "removed": []}

        # List the old and new references then make the diff between them
        old_refs = {
            ref["url"]: ref
            for ref in self.cve_obj.json["cve"]["references"]["reference_data"]
        }
        new_refs = {
            ref["url"]: ref
            for ref in self.cve_json["cve"]["references"]["reference_data"]
        }
        diff = DeepDiff(old_refs, new_refs)

        # New references
        payload["added"] = [
            new_refs[r[6:-2]] for r in diff.get("dictionary_item_added", [])
        ]

        # Removed references
        payload["removed"] = [
            old_refs[r[6:-2]] for r in diff.get("dictionary_item_removed", [])
        ]

        # Changed references (the following code parses the DeepDiff result
        # and extracts the urls of modified references)
        modified_urls = list(
            set(
                [
                    r.split("'")[1]
                    for r in list(diff.get("values_changed", {}).keys())
                    + list(diff.get("iterable_item_added", {}).keys())
                ]
            )
        )
        payload["changed"] = [
            {"old": old_refs[url], "new": new_refs[url]} for url in modified_urls
        ]

        # Create the event with the references changes
        if payload["changed"] or payload["added"] or payload["removed"]:
            event = CveUtil.create_event(
                self.cve_obj, self.cve_json, "references", payload
            )
            return event

        return None
