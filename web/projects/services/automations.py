import re
from datetime import datetime

from django.core.exceptions import ValidationError
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from projects.models import Automation, get_default_automation_config

RESERVED_AUTOMATION_NAMES = frozenset({"add"})
AUTOMATION_NAME_RESERVED_MESSAGE = "This name is reserved."
AUTOMATION_NAME_TAKEN_MESSAGE = "This name already exists."
AUTOMATION_NAME_INVALID_MESSAGE = (
    "Special characters (except dash and underscore) are not accepted"
)

AUTOMATION_WRITE_FIELDS = (
    "name",
    "is_enabled",
    "trigger_type",
    "frequency",
    "schedule_timezone",
    "schedule_time",
    "schedule_weekday",
    "configuration",
)

SCHEDULE_FIELDS = frozenset(
    {"frequency", "schedule_timezone", "schedule_time", "schedule_weekday"}
)

_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9\-_ ]+$")


def _schedule_time_minute(schedule_time):
    """Get the minute of the schedule time"""
    if schedule_time is None:
        return None

    if hasattr(schedule_time, "minute"):
        return schedule_time.minute

    if isinstance(schedule_time, str):
        for fmt in ("%H:%M", "%H:%M:%S"):
            try:
                return datetime.strptime(schedule_time, fmt).time().minute
            except ValueError:
                continue

    return None


def validate_automation_name(name, *, project=None, exclude_automation=None):
    """Validate the automation name"""
    if name in RESERVED_AUTOMATION_NAMES:
        raise ValidationError(AUTOMATION_NAME_RESERVED_MESSAGE)

    if not _NAME_PATTERN.match(name):
        raise ValidationError(AUTOMATION_NAME_INVALID_MESSAGE)

    if project is None:
        return

    # Check if the automation name is already taken
    queryset = Automation.objects.filter(project=project, name=name)
    if exclude_automation is not None:
        queryset = queryset.exclude(pk=exclude_automation.pk)

    if queryset.exists():
        raise ValidationError(AUTOMATION_NAME_TAKEN_MESSAGE)


def validate_conditions_tree(node):
    """Validate the conditions tree"""
    if not isinstance(node, dict):
        raise ValidationError("Condition node must be an object.")

    if "operator" in node:
        if node["operator"] not in ("OR", "AND"):
            raise ValidationError("Operator must be OR or AND.")

        children = node.get("children")
        if not isinstance(children, list):
            raise ValidationError("Children must be a list.")

        for child in children:
            validate_conditions_tree(child)

    elif "type" in node:
        if "value" not in node:
            raise ValidationError("Condition leaf must have 'value'.")

    else:
        raise ValidationError(
            "Condition node must have 'operator' and 'children' or 'type' and 'value'."
        )


def validate_automation_configuration(configuration, *, trigger_type):
    """Validate the automation configuration"""
    if not isinstance(configuration, dict):
        raise ValidationError("Invalid configuration format.")

    if "conditions" not in configuration or "actions" not in configuration:
        raise ValidationError("Configuration must contain 'conditions' and 'actions'.")

    validate_conditions_tree(configuration["conditions"])

    if not isinstance(configuration["actions"], list):
        raise ValidationError("Actions must be a list.")

    if "triggers" in configuration:
        if not isinstance(configuration["triggers"], list):
            raise ValidationError("Triggers must be a list.")
        for trigger in configuration["triggers"]:
            if not isinstance(trigger, str):
                raise ValidationError("Each trigger must be a string.")

    if trigger_type == Automation.TRIGGER_ALERT:
        triggers = configuration.get("triggers") or []
        if not triggers:
            raise ValidationError(
                "At least one event is required for alert automations."
            )
        if not configuration["actions"]:
            raise ValidationError(
                "At least one action is required for alert automations."
            )

    return configuration


def validate_automation_schedule(data, *, trigger_type):
    """Validate the automation schedule"""
    errors = {}
    frequency = data.get("frequency")
    schedule_timezone = data.get("schedule_timezone")
    schedule_time = data.get("schedule_time")
    schedule_weekday = data.get("schedule_weekday")

    if trigger_type == Automation.TRIGGER_REPORT:
        if not frequency:
            errors["frequency"] = ["Frequency is required when trigger type is report."]
        if not schedule_timezone:
            errors["schedule_timezone"] = [
                "Timezone is required when trigger type is report."
            ]
        if not schedule_time:
            errors["schedule_time"] = [
                "Run time is required when trigger type is report."
            ]

    if schedule_timezone:
        try:
            ZoneInfo(schedule_timezone)
        except ZoneInfoNotFoundError:
            errors["schedule_timezone"] = [
                "Invalid timezone, please use an IANA timezone (example: Europe/Paris)."
            ]

    if schedule_time is not None:
        minute = _schedule_time_minute(schedule_time)
        if minute not in (None, 0):
            errors["schedule_time"] = [
                "Run time must be aligned to a full hour (HH:00) because the DAG runs hourly."
            ]

    if (
        trigger_type == Automation.TRIGGER_REPORT
        and frequency == Automation.FREQUENCY_WEEKLY
        and not schedule_weekday
    ):
        errors["schedule_weekday"] = [
            "A weekday is required for weekly report automations."
        ]

    if errors:
        raise ValidationError(errors)


def normalize_automation_schedule_fields(data, *, trigger_type):
    """Normalize the automation schedule fields"""
    normalized = dict(data)

    if trigger_type == Automation.TRIGGER_ALERT:
        normalized["frequency"] = None
        normalized["schedule_timezone"] = None
        normalized["schedule_time"] = None
        normalized["schedule_weekday"] = None
    elif trigger_type == Automation.TRIGGER_REPORT:
        if normalized.get("frequency") == Automation.FREQUENCY_DAILY:
            normalized["schedule_weekday"] = None

    return normalized


def _build_effective_automation_data(attrs, *, instance=None, partial=False):
    """Build the effective automation data"""
    if instance is not None:
        effective = {
            "name": instance.name,
            "is_enabled": instance.is_enabled,
            "trigger_type": instance.trigger_type,
            "frequency": instance.frequency,
            "schedule_timezone": instance.schedule_timezone,
            "schedule_time": instance.schedule_time,
            "schedule_weekday": instance.schedule_weekday,
            "configuration": instance.configuration,
        }
        effective.update(attrs)
        return effective

    if partial:
        raise ValueError("partial updates require an instance")

    effective = {
        "is_enabled": True,
        "trigger_type": Automation.TRIGGER_ALERT,
        "frequency": None,
        "schedule_timezone": None,
        "schedule_time": None,
        "schedule_weekday": None,
        "configuration": get_default_automation_config(),
    }
    effective.update(attrs)
    return effective


def validate_and_normalize_automation_write(
    attrs, *, project, instance=None, partial=False
):
    """Validate and normalize the automation write data"""
    effective = _build_effective_automation_data(
        attrs, instance=instance, partial=partial
    )
    errors = {}

    # Validate the automation name
    try:
        validate_automation_name(
            effective["name"],
            project=project,
            exclude_automation=instance,
        )
    except ValidationError as exc:
        errors["name"] = exc.messages

    # Validate the automation schedule
    trigger_type = effective["trigger_type"]
    try:
        validate_automation_schedule(effective, trigger_type=trigger_type)
    except ValidationError as exc:
        errors.update(exc.message_dict)

    # Validate the automation configuration
    if not partial or "configuration" in attrs:
        configuration = effective.get("configuration")
        if configuration is None:
            configuration = get_default_automation_config()
        try:
            effective["configuration"] = validate_automation_configuration(
                configuration,
                trigger_type=trigger_type,
            )
        except ValidationError as exc:
            errors["configuration"] = exc.messages

    if errors:
        raise ValidationError(errors)

    # Normalize the automation schedule fields
    normalized = normalize_automation_schedule_fields(
        effective, trigger_type=trigger_type
    )

    if partial:
        keys_to_update = set(attrs.keys())
        if "trigger_type" in attrs:
            keys_to_update |= SCHEDULE_FIELDS
        return {
            key: normalized[key]
            for key in keys_to_update
            if key in AUTOMATION_WRITE_FIELDS
        }

    return {key: normalized[key] for key in AUTOMATION_WRITE_FIELDS}
