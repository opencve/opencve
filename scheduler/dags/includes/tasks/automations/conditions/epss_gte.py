from includes.tasks.automations.conditions.base import (
    ConditionEvaluator,
    register_condition,
)


@register_condition("epss_gte")
class EpssGteCondition(ConditionEvaluator):
    def evaluate(self, value, change_details, cve_trackers):
        threshold = float(value or 0)
        metrics = change_details.get("cve_metrics", {})
        epss_data = metrics.get("epss", {}).get("data", {})
        score = epss_data.get("score")
        if score is None:
            return False
        return float(score) >= threshold
