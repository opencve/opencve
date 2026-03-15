import logging
from abc import ABC, abstractmethod
from typing import Any, Dict

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
