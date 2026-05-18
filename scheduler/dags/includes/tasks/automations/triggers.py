import logging
from abc import ABC, abstractmethod

from includes.tasks.automations.utils import (
    get_metrics,
    get_updated_metric_change,
    has_added_values,
)

logger = logging.getLogger(__name__)

TRIGGER_REGISTRY = {}


class TriggerEvaluator(ABC):
    @abstractmethod
    def evaluate(self, change_details, automation) -> bool:
        raise NotImplementedError


def register_trigger(trigger_type: str):
    def _decorator(cls):
        TRIGGER_REGISTRY[trigger_type] = cls()
        return cls

    return _decorator


def evaluate_triggers(triggers, change_details, automation):
    if not triggers:
        return True

    for trigger in triggers:
        evaluator = TRIGGER_REGISTRY.get(trigger)
        if evaluator is None:
            logger.warning("Unknown automation trigger: %s", trigger)
            continue

        try:
            if evaluator.evaluate(change_details, automation):
                return True
        except Exception:
            logger.exception(
                "Trigger evaluation failed trigger=%s automation=%s change=%s",
                trigger,
                automation.get("automation_id"),
                change_details.get("change_id"),
            )

    return False


@register_trigger("cve_enters_project")
class CveEntersProjectTrigger(TriggerEvaluator):
    def evaluate(self, change_details, automation):
        payload = change_details.get("change_payload") or {}
        first_time = payload.get("first_time")
        if not isinstance(first_time, list):
            return False
        subscriptions = set(automation.get("project_subscriptions") or [])
        return bool(subscriptions.intersection(first_time))


@register_trigger("cvss_increased")
class CvssIncreasedTrigger(TriggerEvaluator):
    def evaluate(self, change_details, automation):
        metrics = get_metrics(change_details)
        for metric_name in ("cvssV2_0", "cvssV3_0", "cvssV3_1", "cvssV4_0"):
            old_score, new_score = get_updated_metric_change(metrics, metric_name)
            if (
                old_score is not None
                and new_score is not None
                and new_score > old_score
            ):
                return True
        return False


@register_trigger("cvss_decreased")
class CvssDecreasedTrigger(TriggerEvaluator):
    def evaluate(self, change_details, automation):
        metrics = get_metrics(change_details)
        for metric_name in ("cvssV2_0", "cvssV3_0", "cvssV3_1", "cvssV4_0"):
            old_score, new_score = get_updated_metric_change(metrics, metric_name)
            if (
                old_score is not None
                and new_score is not None
                and new_score < old_score
            ):
                return True
        return False


@register_trigger("epss_increased")
class EpssIncreasedTrigger(TriggerEvaluator):
    def evaluate(self, change_details, automation):
        old_score, new_score = get_updated_metric_change(
            get_metrics(change_details), "epss"
        )
        return old_score is not None and new_score is not None and new_score > old_score


@register_trigger("epss_decreased")
class EpssDecreasedTrigger(TriggerEvaluator):
    def evaluate(self, change_details, automation):
        old_score, new_score = get_updated_metric_change(
            get_metrics(change_details), "epss"
        )
        return old_score is not None and new_score is not None and new_score < old_score


@register_trigger("kev_added")
class KevAddedTrigger(TriggerEvaluator):
    def evaluate(self, change_details, automation):
        metrics = get_metrics(change_details)
        added = metrics.get("added")
        return isinstance(added, dict) and bool(added.get("kev"))


@register_trigger("new_vendor")
class NewVendorTrigger(TriggerEvaluator):
    def evaluate(self, change_details, automation):
        return has_added_values(change_details, "vendors")


@register_trigger("new_product")
class NewProductTrigger(TriggerEvaluator):
    def evaluate(self, change_details, automation):
        return has_added_values(change_details, "cpes")


@register_trigger("new_reference")
class NewReferenceTrigger(TriggerEvaluator):
    def evaluate(self, change_details, automation):
        return has_added_values(change_details, "references")


@register_trigger("new_weakness")
class NewWeaknessTrigger(TriggerEvaluator):
    def evaluate(self, change_details, automation):
        return has_added_values(change_details, "weaknesses")


@register_trigger("description_changed")
class DescriptionChangedTrigger(TriggerEvaluator):
    def evaluate(self, change_details, automation):
        payload = change_details.get("change_payload") or {}
        details = payload.get("description")
        if not isinstance(details, dict):
            return False
        return details.get("old") != details.get("new")


@register_trigger("title_changed")
class TitleChangedTrigger(TriggerEvaluator):
    def evaluate(self, change_details, automation):
        payload = change_details.get("change_payload") or {}
        details = payload.get("title")
        if not isinstance(details, dict):
            return False
        return details.get("old") != details.get("new")
