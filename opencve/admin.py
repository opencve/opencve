import json

import arrow
from difflib import HtmlDiff
from flask import abort
from flask_admin import AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from flask_user import current_user
from sqlalchemy import func
from sqlalchemy.orm import joinedload


class AuthModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.admin

    def inaccessible_callback(self, name, **kwargs):
        abort(404)


class HomeView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.admin

    def inaccessible_callback(self, name, **kwargs):
        abort(404)

    @expose("/")
    def index(self):
        if (not current_user.is_authenticated) or (not current_user.admin):
            abort(404)

        # Import here to avoid circular dependencies
        from opencve.models.users import User

        users_count = User.query.count()

        from .models.reports import Report

        reports_count = Report.query.count()

        from .extensions import db

        # Find number of users per day
        users_by_day = (
            db.session.query(
                func.date_trunc("day", User.created_at), func.count(User.id)
            )
            .group_by(func.date_trunc("day", User.created_at))
            .order_by(func.date_trunc("day", User.created_at))
            .all()
        )

        days = {
            "day": [arrow.get(user[0]).strftime("%d/%m/%y") for user in users_by_day],
            "count": [user[1] for user in users_by_day],
        }

        # Find number of users per month
        users_by_month = (
            db.session.query(
                func.date_trunc("month", User.created_at), func.count(User.id)
            )
            .group_by(func.date_trunc("month", User.created_at))
            .order_by(func.date_trunc("month", User.created_at))
            .all()
        )

        months = {
            "month": [
                arrow.get(month[0]).strftime("%B %Y") for month in users_by_month
            ],
            "count": [month[1] for month in users_by_month],
        }

        # Last week
        week = {"day": days["day"][-7::], "count": days["count"][-7::]}

        return self.render(
            "admin/index.html",
            users_count=users_count,
            reports_count=reports_count,
            week=week,
            days=days,
            months=months,
        )

    @expose("/tasks")
    def tasks(self):
        from .extensions import db
        from .models.tasks import Task

        tasks = (
            db.session.query(Task.created_at, Task.id, func.count(Task.id))
            .join(Task.changes)
            .group_by(Task)
            .order_by(Task.created_at.desc())
            .all()
        )

        return self.render("admin/tasks.html", tasks=tasks)

    @expose("/tasks/<id>")
    def task(self, id):
        from .models.tasks import Task
        from .models.changes import Change

        task = Task.query.get(id)
        changes = (
            Change.query.options(joinedload("cve"))
            .options(joinedload("events"))
            .filter_by(task_id=id)
            .order_by(Change.created_at.desc())
            .all()
        )

        return self.render("admin/task.html", task=task, changes=changes)

    @expose("/changes/<id>")
    def change(self, id):
        from .models.changes import Change

        change = Change.query.get(id)
        previous = (
            Change.query.filter(Change.created_at < change.created_at)
            .filter(Change.cve == change.cve)
            .order_by(Change.created_at.desc())
            .first()
        )

        if previous:
            previous_json = previous.json
        else:
            previous_json = {}

        differ = HtmlDiff(wrapcolumn=100)
        diff = differ.make_table(
            json.dumps(previous_json, sort_keys=True, indent=2).split("\n"),
            json.dumps(change.json, sort_keys=True, indent=2).split("\n"),
            "Old",
            "New",
        )

        return self.render(
            "/admin/change.html", change=change, previous=previous, diff=diff
        )


class UserModelView(AuthModelView):
    page_size = 20
    create_modal = False
    edit_modal = False
    can_view_details = True
    column_filters = column_searchable_list = ["username", "email"]
    column_list = ("username", "email", "created_at", "is_confirmed")


class CveModelView(AuthModelView):
    page_size = 20
    can_create = False
    can_edit = False
    can_delete = False
    can_view_details = True
    column_filters = column_searchable_list = ["cve_id", "summary", "cvss2", "cvss3"]
    column_list = ("cve_id", "updated_at", "cvss2", "cvss3")


class EventModelView(AuthModelView):
    page_size = 20
    can_create = False
    can_edit = False
    can_delete = False
    can_view_details = True
    column_list = ("cve", "type", "created_at")


class VendorModelView(AuthModelView):
    page_size = 20
    create_modal = False
    edit_modal = False
    can_view_details = True
    column_list = ["name", "created_at"]


class ProductModelView(AuthModelView):
    page_size = 20
    create_modal = False
    edit_modal = False
    can_view_details = True
    column_list = ["name", "vendor", "created_at"]
