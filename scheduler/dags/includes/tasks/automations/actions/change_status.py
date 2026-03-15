import logging

from includes.tasks.automations.actions.base import ActionExecutor, register_action
from includes.tasks.automations.actions.common import (
    get_item_cve_ids,
    upsert_tracker_records,
)

logger = logging.getLogger(__name__)


@register_action("change_status")
class ChangeStatusAction(ActionExecutor):
    async def execute(self, action, context):
        status = action.get("value")
        if not status:
            logger.warning("No status specified for change_status action")
            return

        cve_id_strings = get_item_cve_ids(
            context["changes"], context["item_changes_details"]
        )
        upsert_tracker_records(
            postgres_hook=context["postgres_hook"],
            project_id=context["automation"]["project_id"],
            cve_id_strings=cve_id_strings,
            status=status,
        )
