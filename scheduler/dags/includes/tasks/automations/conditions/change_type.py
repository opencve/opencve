from includes.tasks.automations.conditions.base import (
    ConditionEvaluator,
    register_condition,
)


# TODO: je pense que kev_added doit tomber dans metrics
# TODO: c'est quoi la diff avec TRIGGER_TO_CHANGE_TYPES ?
CONDITION_TO_CHANGE_TYPES = {
    "cve_enters_project": {"created"},
    "cvss_increased": {"metrics"},
    "cvss_decreased": {"metrics"},
    "cvss_increased_by": {"metrics"},
    "epss_increased": {"metrics"},
    "epss_decreased": {"metrics"},
    "kev_added": {"kev"},
    "new_vendor": {"vendors"},
    "new_product": {"cpes"},
    "description_changed": {"description"},
    "summary_changed": {"summary"},
    "title_changed": {"title"},
    "new_reference": {"references"},
    "new_weakness": {"weaknesses"},
}


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


for _condition_type in CONDITION_TO_CHANGE_TYPES:
    _register_change_type_condition(_condition_type)
