from flask import request, render_template

from opencve.controllers.main import main
from opencve.controllers.products import ProductController
from opencve.controllers.vendors import VendorController


@main.route("/vendors")
def vendors():
    vendors, _, pagination_v = VendorController.list(request.args)
    products, _, pagination_p = ProductController.list(request.args)

    return render_template(
        "vendors.html",
        vendors=vendors,
        products=products,
        pagination_v=pagination_v,
        pagination_p=pagination_p,
    )
