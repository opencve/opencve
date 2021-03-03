from flask import request, render_template

from opencve.controllers.main import main
from opencve.controllers.vendors import VendorController
from opencve.utils import get_vendors_letters


@main.route("/vendors")
def vendors():
    vendors, _, pagination = VendorController.list(request.args)
    return render_template(
        "vendors.html",
        vendors=vendors,
        letters=get_vendors_letters(),
        pagination=pagination,
    )
