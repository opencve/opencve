class MitreEvents(object):
    def __init__(self, old, new):
        self.old = old
        self.new = new

    def get_name(self):
        return self.__class__.__name__

    def execute(self):
        raise NotImplementedError


class Summary(MitreEvents):
    @staticmethod
    def get_description(cve_data):
        # If no descriptions, take the rejected reasons
        cna = cve_data["containers"]["cna"]
        descriptions = cna.get("descriptions") or cna["rejectedReasons"]

        # In case of multiple languages, keep the EN one
        if len(descriptions) > 1:
            descriptions = [d for d in descriptions if d["lang"] in ("en", "en-US")]

        return descriptions[0]["value"]

    def execute(self):
        new_summary = self.get_description(self.new)
        old_summary = self.get_description(self.old)

        if new_summary != old_summary:
            return {
                "type": "summary",
                "details": {"old": old_summary, "new": new_summary},
            }
