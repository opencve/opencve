from opencve.checks import BaseCheck
from opencve.commands.utils import CveUtil
from opencve.extensions import db


class Summary(BaseCheck):
    @staticmethod
    def get_flat_descriptions(descriptions):
        return {d["lang"]: d["value"] for d in descriptions}

    @staticmethod
    def get_descriptions_payload(old, new):
        payload = {"changed": {}, "added": {}, "removed": {}}

        added = list(set(new.keys()) - set(old.keys()))
        payload["added"] = {lang: new[lang] for lang in added}

        removed = list(set(old.keys()) - set(new.keys()))
        payload["removed"] = {lang: old[lang] for lang in removed}

        for lang, desc in new.items():
            if lang in old.keys() and desc != old[lang]:
                payload["changed"][lang] = {
                    "old": old[lang],
                    "new": new[lang],
                }

        return payload

    def execute(self):
        old_summary = self.get_flat_descriptions(self.cve_obj.json["descriptions"])
        new_summary = self.get_flat_descriptions(self.cve_json["descriptions"])
        payload = self.get_descriptions_payload(old_summary, new_summary)

        # In case of multiple languages, keep the EN one
        descriptions = self.cve_json["descriptions"]
        if len(descriptions) > 1:
            descriptions = [d for d in descriptions if d["lang"] in ("en", "en-US")]
        summary = descriptions[0]["value"]

        # Check if the summary has changed
        if payload["added"] or payload["removed"] or payload["changed"]:
            self.cve_obj.summary = summary
            db.session.commit()

            # Create a 'summary' event
            event = CveUtil.create_event(
                self.cve_obj,
                self.cve_json,
                "summary",
                payload,
            )
            return event

        return None
