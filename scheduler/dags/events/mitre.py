from events import BaseEvents


class MitreEvents(BaseEvents):
    pass


class MitreSummary(MitreEvents):
    def execute(self):
        old = self.old["containers"]["cna"]
        old_descriptions = old.get("descriptions") or old["rejectedReasons"]
        old_summary = self.get_flat_descriptions(old_descriptions)

        new = self.new["containers"]["cna"]
        new_descriptions = new.get("descriptions") or new["rejectedReasons"]
        new_summary = self.get_flat_descriptions(new_descriptions)

        payload = self.get_descriptions_payload(old_summary, new_summary)

        if payload["added"] or payload["removed"] or payload["changed"]:
            return {"type": "mitre_summary", "details": payload}
