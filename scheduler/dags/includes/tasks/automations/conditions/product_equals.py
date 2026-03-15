from includes.constants import PRODUCT_SEPARATOR
from includes.tasks.automations.conditions.base import (
    ConditionEvaluator,
    register_condition,
)


@register_condition("product_equals")
class ProductEqualsCondition(ConditionEvaluator):
    def evaluate(self, value, change_details, cve_trackers):
        expected_product = str(value or "").lower()
        vendors = change_details.get("cve_vendors", [])
        for vendor in vendors:
            if PRODUCT_SEPARATOR not in vendor:
                continue
            _, product = vendor.split(PRODUCT_SEPARATOR, 1)
            if product.lower() == expected_product:
                return True
        return False
