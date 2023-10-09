from nested_lookup import nested_lookup

from events import BaseEvents
from utils import vendors_conf_to_flat, weaknesses_to_flat


class NvdEvents(BaseEvents):
    pass


class NvdSummary(NvdEvents):
    def execute(self):
        old_summary = self.get_flat_descriptions(self.old.get("descriptions"))
        new_summary = self.get_flat_descriptions(self.new.get("descriptions"))
        payload = self.get_descriptions_payload(old_summary, new_summary)

        if payload["added"] or payload["removed"] or payload["changed"]:
            return {"type": "nvd_summary", "details": payload}


class NvdFirstTime(NvdEvents):
    def execute(self):
        old_confs = vendors_conf_to_flat(self.old.get("configurations"))
        new_confs = vendors_conf_to_flat(self.new.get("configurations"))

        payload = list(set(new_confs) - set(old_confs))
        if payload:
            return {"type": "nvd_first_time", "details": payload}


class NvdCvss(NvdEvents):
    def execute(self):
        old_metrics = self.old.get("metrics")
        new_metrics = self.new.get("metrics")
        print(new_metrics)

        # Check the new CVSS scores
        new = {}
        if "cvssMetricV31" in new_metrics:
            new["v31"] = new_metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]

        if "cvssMetricV30" in new_metrics:
            new["v30"] = new_metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]

        if "cvssMetricV2" in new_metrics:
            new["v2"] = new_metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

        # Retrieve the old CVSS scores
        old = {}
        if "cvssMetricV31" in old_metrics:
            old["v31"] = old_metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]

        if "cvssMetricV30" in old_metrics:
            old["v30"] = old_metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]

        if "cvssMetricV2" in old_metrics:
            old["v2"] = old_metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

        # If at least one version has changed, update the CVE
        if old != new:
            return {"type": "nvd_cvss", "details": {"old": old, "new": new}}


class NvdCwes(NvdEvents):
    def execute(self):
        new_weaknesses = weaknesses_to_flat(self.new.get("weaknesses"))
        old_weaknesses = weaknesses_to_flat(self.old.get("weaknesses"))

        payload = {
            "added": list(set(new_weaknesses) - set(old_weaknesses)),
            "removed": list(set(old_weaknesses) - set(new_weaknesses)),
        }

        if payload["added"] or payload["removed"]:
            return {"type": "nvd_cwes", "details": payload}


class NvdReference(NvdEvents):
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
            return {"type": "nvd_references", "details": payload}


class NvdCpe(NvdEvents):
    def execute(self):
        old_cpes = nested_lookup("criteria", self.old.get("configurations"))
        new_cpes = nested_lookup("criteria", self.new.get("configurations"))

        # TODO: enhance this event check
        # Only the CPEs uri (ie `cpe:2.3:a:opencveio:opencve:*:*:*:*:*:*:*:*`)
        # are checked. If a CPE uri is added or removed this check will see it,
        # but other fields can also be changed (`versionEndExcluding`, `vulnerable`...).
        # In this case no event is created and the user can miss information.
        payload = {
            "added": list(set(new_cpes) - set(old_cpes)),
            "removed": list(set(old_cpes) - set(new_cpes)),
        }

        if payload["added"] or payload["removed"]:
            return {"type": "nvd_cpes", "details": payload}
