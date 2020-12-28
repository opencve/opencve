from flask import current_app as app
from flask import redirect, render_template, request, url_for
from flask_paginate import Pagination

from opencve.controllers.main import main
from opencve.models.products import Product
from opencve.models.vendors import Vendor


@main.route("/vendors/<vendor>/products")
def products(vendor):
    vendor = Vendor.query.filter_by(name=vendor).first()
    if not vendor:
        return redirect(url_for("main.vendors"))

    q = Product.query.filter_by(vendor=vendor)

    # Search by term
    if request.args.get("search"):
        search = request.args.get("search").lower().replace("%", "").replace("_", "")
        q = q.filter(Product.name.like("%{}%".format(search)))

    page = request.args.get("page", type=int, default=1)
    objects = q.order_by(Product.name.asc()).paginate(
        page, app.config["PRODUCTS_PER_PAGE"], True
    )
    pagination = Pagination(
        page=page,
        total=objects.total,
        per_page=app.config["PRODUCTS_PER_PAGE"],
        record_name="products",
        css_framework="bootstrap3",
    )

    return render_template(
        "products.html", products=objects, vendor=vendor, pagination=pagination
    )
