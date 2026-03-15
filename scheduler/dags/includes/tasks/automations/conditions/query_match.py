import logging

from includes.tasks.automations.conditions.base import (
    ConditionEvaluator,
    register_condition,
)

logger = logging.getLogger(__name__)


@register_condition("query_match")
class QueryMatchCondition(ConditionEvaluator):
    def evaluate(self, value, change_details, cve_trackers):
        logger.warning("Condition query_match is not implemented yet, skipping filter")
        return True
