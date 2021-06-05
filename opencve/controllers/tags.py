import string

from flask import abort

from opencve.controllers.base import BaseController
from opencve.models.tags import UserTag


class UserTagController(BaseController):
    model = UserTag
    order = UserTag.name.asc()
    per_page_param = "TAGS_PER_PAGE"
    schema = {
        "user_id": {"type": str},
        "name": {"type": str},
    }

    @classmethod
    def build_query(cls, args):
        return cls.model.query.filter_by(user_id=args.get("user_id")), {}
