import warnings

from opencve.checks import BaseCheck
from opencve.commands.utils import CveUtil
from opencve.extensions import cel, db

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

        # Check exploit
        if (payload["changed"] or payload["added"]
            and (cel.app.config["EXPLOIT_LINK"] or cel.app.config["EXPLOIT_TAG"])):
            exploit_find = False
            for refs_cve in self.cve_json["cve"]["references"]["reference_data"]:
                if (
                    cel.app.config["EXPLOIT_TAG_NIST"]
                    and "tags" in refs_cve
                    and cel.app.config["EXPLOIT_TAG_NIST"] in refs_cve["tags"]):
                    self.cve_obj.exploit = True
                    db.session.commit()
                    break
                if (
                    cel.app.config["EXPLOIT_LINK"]
                    and "url" in refs_cve):
                    for links_refs in cel.app.config["EXPLOIT_LINK"].split(','):
                        if links_refs in refs_cve["url"].lower():
                            exploit_find = True
                            break
                    if exploit_find:
                        self.cve_obj.exploit = True
                        db.session.commit()
                        break
        # Create the event with the references changes
        if payload["changed"] or payload["added"] or payload["removed"]:
            event = CveUtil.create_event(
                self.cve_obj, self.cve_json, "references", payload
            )
            return event

        return None
