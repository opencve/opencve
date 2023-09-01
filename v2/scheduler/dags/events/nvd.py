from nested_lookup import nested_lookup

from utils import vendors_conf_to_flat, weaknesses_to_flat


class NvdEvents(object):
    def __init__(self, old, new):
        self.old = old
        self.new = new

    def get_name(self):
        return self.__class__.__name__

    def execute(self):
        raise NotImplementedError


class FirstTime(NvdEvents):
    def execute(self):
        old_confs = vendors_conf_to_flat(self.old.get("configurations"))
        new_confs = vendors_conf_to_flat(self.new.get("configurations"))

        payload = list(set(new_confs) - set(old_confs))
        if payload:
            return {"type": "first_time", "details": payload}


class Cvss(NvdEvents):
    def execute(self):
        old_metrics = self.old.get("metrics")
        new_metrics = self.new.get("metrics")

        # Check the new CVSS scores
        new = {}
        if hasattr(new_metrics, "cvssMetricV31"):
            new["v31"] = new_metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]

        if hasattr(new_metrics, "cvssMetricV30"):
            new["v30"] = new_metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]

        if hasattr(new_metrics, "cvssMetricV2"):
            new["v2"] = new_metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

        # Retrieve the old CVSS scores
        old = {}
        if hasattr(old_metrics, "cvssMetricV31"):
            old["v31"] = old_metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]

        if hasattr(old_metrics, "cvssMetricV30"):
            old["v30"] = old_metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]

        if hasattr(old_metrics, "cvssMetricV2"):
            old["v2"] = old_metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

        # If at least one version has changed, update the CVE
        if old != new:
            return {"type": "cvss", "details": {"old": old, "new": new}}


class Cwes(NvdEvents):
    def execute(self):
        new_weaknesses = weaknesses_to_flat(self.new.get("weaknesses"))
        old_weaknesses = weaknesses_to_flat(self.old.get("weaknesses"))

        payload = {
            "added": list(set(new_weaknesses) - set(old_weaknesses)),
            "removed": list(set(old_weaknesses) - set(new_weaknesses)),
        }

        if payload:
            return {"type": "cwes", "details": payload}


class Reference(NvdEvents):
    def execute(self):
        payload = {"changed": [], "added": [], "removed": []}

        old_refs = {ref["url"]: ref for ref in self.old.get("references")}
        new_refs = {ref["url"]: ref for ref in self.new.get("references")}

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

        if payload["changed"] or payload["added"] or payload["removed"]:
            return {"type": "references", "details": payload}


class Cpe(NvdEvents):
    def execute(self):
        old_cpes = nested_lookup("cpe23Uri", self.old.get("configurations"))
        new_cpes = nested_lookup("cpe23Uri", self.new.get("configurations"))

        payload = {
            "added": list(set(new_cpes) - set(old_cpes)),
            "removed": list(set(old_cpes) - set(new_cpes)),
        }

        if payload["added"] or payload["removed"]:
            return {"type": "cpes", "details": payload}
