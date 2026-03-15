from includes.tasks.automations.conditions.base import (
    ConditionEvaluator,
    register_condition,
)


@register_condition("cve_unassigned")
class CveUnassignedCondition(ConditionEvaluator):
    def evaluate(self, value, change_details, cve_trackers):
        cve_id = change_details.get("cve_id")
        if cve_id is None:
            return False
        if not cve_trackers:
            return True
        tracker = cve_trackers.get(cve_id)
        if tracker is None:
            return True
        return tracker.get("assignee_id") is None
