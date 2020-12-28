from flask import current_app as app
from flask import render_template, request
from flask_paginate import Pagination

from opencve.controllers.main import main
from opencve.models.cwe import Cwe


@main.route("/cwe")
def cwes():
    q = Cwe.query

    # Filter the list of CWE
    if request.args.get("search"):
        search = request.args.get("search").strip().lower()

        # By ID or by string
        search = search[4:] if search.startswith("cwe-") else search
        try:
            search = int(search)
            q = q.filter_by(cwe_id=f"CWE-{search}")
        except ValueError:
            q = q.filter(Cwe.name.ilike("%{}%".format(search)))

    page = request.args.get("page", type=int, default=1)
    objects = q.order_by(Cwe.cwe_id.desc()).paginate(
        page, app.config["CWES_PER_PAGE"], True
    )
    pagination = Pagination(
        page=page,
        total=objects.total,
        per_page=app.config["CWES_PER_PAGE"],
        record_name="cwes",
        css_framework="bootstrap3",
    )

    return render_template("cwes.html", cwes=objects, pagination=pagination)
