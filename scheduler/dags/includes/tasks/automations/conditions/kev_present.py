from includes.tasks.automations.conditions.base import (
    ConditionEvaluator,
    register_condition,
)


@register_condition("kev_present")
class KevPresentCondition(ConditionEvaluator):
    def evaluate(self, value, change_details, cve_trackers):
        metrics = change_details.get("cve_metrics", {})
        kev_data = metrics.get("kev", {}).get("data", {})
        return bool(kev_data)
