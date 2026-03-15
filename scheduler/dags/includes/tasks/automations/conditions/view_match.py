import logging

from includes.tasks.automations.conditions.base import (
    ConditionEvaluator,
    register_condition,
)

logger = logging.getLogger(__name__)


@register_condition("view_match")
class ViewMatchCondition(ConditionEvaluator):
    def evaluate(self, value, change_details, cve_trackers):
        logger.warning("Condition view_match is not implemented yet, skipping filter")
        return True
