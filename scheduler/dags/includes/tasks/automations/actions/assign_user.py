import logging

from includes.tasks.automations.actions.base import ActionExecutor, register_action
from includes.tasks.automations.actions.common import (
    get_item_cve_ids,
    upsert_tracker_records,
)

logger = logging.getLogger(__name__)


@register_action("assign_user")
class AssignUserAction(ActionExecutor):
    async def execute(self, action, context):
        assignee_id = action.get("value")
        if not assignee_id:
            logger.warning("No assignee specified for assign_user action")
            return

        cve_id_strings = get_item_cve_ids(
            context["changes"], context["item_changes_details"]
        )
        upsert_tracker_records(
            postgres_hook=context["postgres_hook"],
            project_id=context["automation"]["project_id"],
            cve_id_strings=cve_id_strings,
            assignee_id=assignee_id,
        )
