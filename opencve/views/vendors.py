from flask import request, render_template

from opencve.controllers.main import main
from opencve.controllers.vendors import VendorController


@main.route("/vendors")
def vendors():
    vendors, metas, pagination = VendorController.list(request.args)
    return render_template(
        "vendors.html",
        vendors=vendors,
        letters=metas.get("letters"),
        pagination=pagination,
    )
