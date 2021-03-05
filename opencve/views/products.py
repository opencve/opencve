from flask import request, render_template

from opencve.controllers.main import main
from opencve.controllers.products import ProductController


@main.route("/vendors/<vendor>/products")
def products(vendor):
    products, _, pagination = ProductController.list({**request.args, "vendor": vendor})

    return render_template(
        "products.html",
        products=products,
        vendor=vendor,
        pagination=pagination,
    )
