import logging

from includes.tasks.automations.actions.base import ActionExecutor, register_action

logger = logging.getLogger(__name__)


@register_action("generate_report")
class GenerateReportAction(ActionExecutor):
    async def execute(self, action, context):
        if not action.get("value", False):
            return
        logger.info(
            "generate_report action requested for automation '%s' with %s matched changes",
            context["automation"]["automation_name"],
            len(context["changes"]),
        )
