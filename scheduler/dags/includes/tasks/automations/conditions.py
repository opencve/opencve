import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict

from includes.constants import (
    CONDITION_TO_CHANGE_TYPES,
    CVSS_VERSION_MAP,
    PRODUCT_SEPARATOR,
)

logger = logging.getLogger(__name__)

CONDITION_REGISTRY = {}


class ConditionEvaluator(ABC):
    @abstractmethod
    def evaluate(self, value: Any, change_details: Dict, cve_trackers: Dict) -> bool:
        raise NotImplementedError


def register_condition(condition_type: str):
    def _decorator(cls):
        CONDITION_REGISTRY[condition_type] = cls()
        return cls

    return _decorator


def evaluate_condition_node(
    node: Dict, change_details: Dict, cve_trackers: Dict
) -> bool:
    condition_type = node.get("type")
    evaluator = CONDITION_REGISTRY.get(condition_type)
    if evaluator is None:
        logger.warning("Unknown automation condition type: %s", condition_type)
        return False
    return evaluator.evaluate(node.get("value"), change_details, cve_trackers)


def evaluate_condition_tree(
    tree: Dict, change_details: Dict, cve_trackers: Dict
) -> bool:
    if not tree:
        return False

    if "type" in tree:
        return evaluate_condition_node(tree, change_details, cve_trackers)

    operator = tree.get("operator")
    children = tree.get("children") or []

    if operator == "OR":
        if not children:
            return False
        return any(
            evaluate_condition_tree(child, change_details, cve_trackers)
            for child in children
        )

    if operator == "AND":
        return all(
            evaluate_condition_tree(child, change_details, cve_trackers)
            for child in children
        )

    logger.warning("Unknown automation operator: %s", operator)
    return False


class ChangeTypeCondition(ConditionEvaluator):
    condition_type = None

    def evaluate(self, value, change_details, cve_trackers):
        expected = CONDITION_TO_CHANGE_TYPES[self.condition_type]
        change_types = set(change_details.get("change_types") or [])
        return bool(change_types.intersection(expected))


def _register_change_type_condition(condition_type):
    evaluator_cls = type(
        f"{condition_type.title().replace('_', '')}Condition",
        (ChangeTypeCondition,),
        {"condition_type": condition_type},
    )
    register_condition(condition_type)(evaluator_cls)


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


@register_condition("kev_present")
class KevPresentCondition(ConditionEvaluator):
    def evaluate(self, value, change_details, cve_trackers):
        metrics = change_details.get("cve_metrics", {})
        kev_data = metrics.get("kev", {}).get("data", {})
        return bool(kev_data)


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


@register_condition("query_match")
class QueryMatchCondition(ConditionEvaluator):
    def evaluate(self, value, change_details, cve_trackers):
        logger.warning("Condition query_match is not implemented yet, skipping filter")
        return True


@register_condition("view_match")
class ViewMatchCondition(ConditionEvaluator):
    def evaluate(self, value, change_details, cve_trackers):
        logger.warning("Condition view_match is not implemented yet, skipping filter")
        return True


for _condition_type in CONDITION_TO_CHANGE_TYPES:
    _register_change_type_condition(_condition_type)
