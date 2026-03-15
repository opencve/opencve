from includes.constants import PRODUCT_SEPARATOR
from includes.tasks.automations.conditions.base import (
    ConditionEvaluator,
    register_condition,
)


@register_condition("vendor_equals")
class VendorEqualsCondition(ConditionEvaluator):
    def evaluate(self, value, change_details, cve_trackers):
        expected_vendor = str(value or "").lower()
        vendors = change_details.get("cve_vendors", [])
        return any(
            vendor.lower() == expected_vendor
            for vendor in vendors
            if PRODUCT_SEPARATOR not in vendor
        )
