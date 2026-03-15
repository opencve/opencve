from datetime import datetime, timezone

from includes.tasks.automations.conditions.base import (
    ConditionEvaluator,
    register_condition,
)


@register_condition("cve_newer_than")
class CveNewerThanCondition(ConditionEvaluator):
    def evaluate(self, value, change_details, cve_trackers):
        cve_id = change_details.get("cve_id", "")
        try:
            threshold_days = int(value)
            cve_year = int(cve_id.split("-")[1])
        except (TypeError, ValueError, IndexError):
            return False

        current_year = datetime.now(tz=timezone.utc).year
        if cve_year >= current_year:
            return True
        return threshold_days > 365 and cve_year >= current_year - 1
