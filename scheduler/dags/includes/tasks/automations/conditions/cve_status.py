from includes.tasks.automations.conditions.base import (
    ConditionEvaluator,
    register_condition,
)


@register_condition("cve_status")
class CveStatusCondition(ConditionEvaluator):
    def evaluate(self, value, change_details, cve_trackers):
        cve_id = change_details.get("cve_id")
        if cve_id is None or not cve_trackers:
            return False
        tracker = cve_trackers.get(cve_id)
        if tracker is None:
            return False
        return tracker.get("status") == value
