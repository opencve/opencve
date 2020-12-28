import json

from flask import current_app as app
from flask import redirect, render_template, request, url_for
from flask_paginate import Pagination
from sqlalchemy import and_

from opencve.constants import PRODUCT_SEPARATOR
from opencve.controllers.main import main
from opencve.models.cve import Cve
from opencve.models.products import Product
from opencve.models.vendors import Vendor
from opencve.utils import convert_cpes


@main.route("/cve")
def cves():
    vendor = None
    product = None
    q = Cve.query

    # Search
    if request.args.get("search"):
        q = q.filter(Cve.summary.like("%{}%".format(request.args.get("search"))))

    # Filter by CWE
    if request.args.get("cwe"):
        try:
            q = q.filter(Cve.cwes.contains([request.args.get("cwe")]))
        except ValueError:
            return redirect(url_for("main.cves"))

    # Filter by CVSS score
    if request.args.get("cvss") and request.args.get("cvss").lower() in [
        "low",
        "medium",
        "high",
    ]:
        if request.args.get("cvss").lower() == "low":
            q = q.filter(and_(Cve.cvss3 >= 0, Cve.cvss3 <= 3.9))

        if request.args.get("cvss").lower() == "medium":
            q = q.filter(and_(Cve.cvss3 >= 4.0, Cve.cvss3 <= 7.4))

        if request.args.get("cvss").lower() == "high":
            q = q.filter(and_(Cve.cvss3 >= 7.5, Cve.cvss3 <= 10))

    # Filter by vendor and product
    if request.args.get("vendor") and request.args.get("product"):
        vendor = Vendor.query.filter_by(name=request.args.get("vendor")).first()
        if not vendor:
            return redirect(url_for("main.cves"))

        product = Product.query.filter_by(
            name=request.args.get("product"), vendor_id=vendor.id
        ).first()
        if not product:
            return redirect(url_for("main.cves"))

        q = q.filter(
            Cve.vendors.contains([f"{vendor.name}{PRODUCT_SEPARATOR}{product.name}"])
        )

    # Filter by vendor
    elif request.args.get("vendor"):
        vendor = Vendor.query.filter_by(name=request.args.get("vendor")).first()
        if not vendor:
            return redirect(url_for("main.cves"))
        q = q.filter(Cve.vendors.contains([vendor.name]))

    page = request.args.get("page", type=int, default=1)
    objects = q.order_by(Cve.updated_at.desc()).paginate(
        page, app.config["CVES_PER_PAGE"], True
    )
    pagination = Pagination(
        page=page,
        total=objects.total,
        per_page=app.config["CVES_PER_PAGE"],
        record_name="cves",
        css_framework="bootstrap3",
    )

    return render_template(
        "cves.html", cves=objects, vendor=vendor, product=product, pagination=pagination
    )


@main.route("/cve/<cve_id>")
def cve(cve_id):
    q = Cve.query

    # Search the CVE
    cve = q.filter_by(cve_id=cve_id).first()

    if not cve:
        return redirect(url_for("main.cves"))

    # Nested dict of vendors and their products
    vendors = convert_cpes(cve.json["configurations"])

    return render_template(
        "cve.html", cve=cve, cve_dumped=json.dumps(cve.json), vendors=vendors
    )
