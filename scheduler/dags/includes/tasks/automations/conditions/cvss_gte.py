from includes.tasks.automations.conditions.base import (
    ConditionEvaluator,
    register_condition,
)


CVSS_VERSION_MAP = {
    "v2.0": "cvssV2_0",
    "v3.0": "cvssV3_0",
    "v3.1": "cvssV3_1",
    "v4.0": "cvssV4_0",
}


@register_condition("cvss_gte")
class CvssGteCondition(ConditionEvaluator):
    def evaluate(self, value, change_details, cve_trackers):
        if isinstance(value, dict):
            version = value.get("version", "v3.1")
            threshold = float(value.get("value", 0))
        else:
            version = "v3.1"
            threshold = float(value or 0)

        metric_key = CVSS_VERSION_MAP.get(version, "cvssV3_1")
        metrics = change_details.get("cve_metrics", {})
        metric_data = metrics.get(metric_key, {}).get("data", {})
        score = metric_data.get("score")
        if score is None:
            return False
        return float(score) >= threshold
