import logging

from includes.tasks.automations.actions.base import ActionExecutor, register_action

logger = logging.getLogger(__name__)


@register_action("generate_pdf")
class GeneratePdfAction(ActionExecutor):
    async def execute(self, action, context):
        if not action.get("value", False):
            return
        logger.info(
            "generate_pdf action requested for automation '%s' with %s matched changes",
            context["automation"]["automation_name"],
            len(context["changes"]),
        )
