import logging
from abc import ABC, abstractmethod
from typing import Dict

logger = logging.getLogger(__name__)

ACTION_REGISTRY = {}


class ActionExecutor(ABC):
    @abstractmethod
    async def execute(self, action: Dict, context: Dict) -> None:
        raise NotImplementedError


def register_action(action_type: str):
    def _decorator(cls):
        ACTION_REGISTRY[action_type] = cls()
        return cls

    return _decorator


async def execute_action(action: Dict, context: Dict) -> None:
    action_type = action.get("type")
    executor = ACTION_REGISTRY.get(action_type)
    if executor is None:
        logger.warning("Unknown automation action type: %s", action_type)
        return
    await executor.execute(action, context)
