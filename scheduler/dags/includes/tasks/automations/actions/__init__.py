"""Actions registry bootstrap for automations."""

from includes.tasks.automations.actions.base import execute_action  # noqa: F401

# Import modules for side-effect registration.
from includes.tasks.automations.actions import assign_user  # noqa: F401
from includes.tasks.automations.actions import change_status  # noqa: F401
from includes.tasks.automations.actions import generate_pdf  # noqa: F401
from includes.tasks.automations.actions import generate_report  # noqa: F401
from includes.tasks.automations.actions import include_ai_summary  # noqa: F401
from includes.tasks.automations.actions import send_notification  # noqa: F401
