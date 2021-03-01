from flask import abort, current_app as app
from flask_paginate import Pagination
from werkzeug.datastructures import ImmutableMultiDict


class BaseController(object):
    model = None
    order = None
    per_page_param = None
    schema = {}

    @classmethod
    def build_query(cls, args):
        return cls.model.query, {}

    @classmethod
    def parse_args(cls, args):
        args = ImmutableMultiDict(args)

        parsed_args = {"page": args.get("page", type=int, default=1)}

        for key in args.keys():
            if key in cls.schema.keys():
                parsed_args[key] = args.get(
                    key,
                    type=cls.schema.get(key).get("type"),
                    default=cls.schema.get(key).get("default"),
                )
        return parsed_args

    @classmethod
    def get(cls, filters):
        obj = cls.model.query.filter_by(**filters).first()
        if not obj:
            abort(404, "Not found.")
        return obj

    @classmethod
    def list(cls, args={}):
        args = cls.parse_args(args)
        query, metas = cls.build_query(args)

        objects = query.order_by(cls.order).paginate(
            args.get("page"), app.config[cls.per_page_param], True
        )

        pagination = Pagination(
            page=args.get("page"),
            total=objects.total,
            per_page=app.config[cls.per_page_param],
            record_name="objects",
            css_framework="bootstrap3",
        )

        return objects, metas, pagination

    @classmethod
    def list_items(cls, args={}):
        objects, _, _ = cls.list(args)
        return objects.items
