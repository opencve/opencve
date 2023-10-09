class BaseEvents(object):
    def __init__(self, old, new):
        self.old = old
        self.new = new

    def get_name(self):
        return self.__class__.__name__

    def execute(self):
        raise NotImplementedError

    @staticmethod
    def get_flat_descriptions(descriptions):
        return {d["lang"]: d["value"] for d in descriptions}

    @staticmethod
    def get_descriptions_payload(old, new):
        """
        The format of the descriptions is the same for NVD and MITRE,
        so we can reuse the same code for both sources.
        """
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

