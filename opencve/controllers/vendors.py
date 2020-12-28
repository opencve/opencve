import string

from flask import current_app as app
from flask import redirect, render_template, request, url_for
from flask_paginate import Pagination

from opencve.controllers.main import main
from opencve.models.vendors import Vendor


@main.route("/vendors")
def vendors():
    letters = list(string.ascii_lowercase + "@" + string.digits)
    letter = request.args.get("l")

    q = Vendor.query

    # Search by term
    if request.args.get("search"):
        search = request.args.get("search").lower().replace("%", "").replace("_", "")
        q = q.filter(Vendor.name.like("%{}%".format(search)))

    # Search by letter
    if letter:
        if letter not in letters:
            return redirect(url_for("main.vendors"))

        q = q.filter(Vendor.name.like("{}%".format(letter)))

    page = request.args.get("page", type=int, default=1)
    objects = q.order_by(Vendor.name.asc()).paginate(
        page, app.config["VENDORS_PER_PAGE"], True
    )
    pagination = Pagination(
        page=page,
        total=objects.total,
        per_page=app.config["VENDORS_PER_PAGE"],
        record_name="vendors",
        css_framework="bootstrap3",
    )

    return render_template(
        "vendors.html", vendors=objects, letters=letters, pagination=pagination
    )
