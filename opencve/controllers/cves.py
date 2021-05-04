import json

from flask import current_app as app
from flask import abort, redirect, render_template, request, url_for
from flask_paginate import Pagination
from sqlalchemy import and_

from opencve.constants import PRODUCT_SEPARATOR
from opencve.controllers.base import BaseController
from opencve.controllers.main import main
from opencve.models.cve import Cve
from opencve.models.products import Product
from opencve.models.vendors import Vendor

from opencve.models.cwe import Cwe


class CveController(BaseController):
    model = Cve
    order = Cve.updated_at.desc()
    per_page_param = "CVES_PER_PAGE"
    schema = {
        "search": {"type": str},
        "vendor": {"type": str},
        "product": {"type": str},
        "cvss": {"type": str},
        "cwe": {"type": str},
    }

    @classmethod
    def build_query(cls, args):
        vendor = None
        product = None
        query = Cve.query

        # Filter by keyword
        if args.get("search"):
            query = query.filter(Cve.summary.like("%{}%".format(args.get("search"))))

        # Filter by CWE
        if args.get("cwe"):
            query = query.filter(Cve.cwes.contains([args.get("cwe")]))

        # Filter by CVSS score
        if args.get("cvss") and args.get("cvss").lower() in [
            "none",
            "low",
            "medium",
            "high",
            "critical",
        ]:
            if args.get("cvss").lower() == "none":
                query = query.filter(Cve.cvss3 == None)

            if args.get("cvss").lower() == "low":
                query = query.filter(and_(Cve.cvss3 >= 0.1, Cve.cvss3 <= 3.9))

            if args.get("cvss").lower() == "medium":
                query = query.filter(and_(Cve.cvss3 >= 4.0, Cve.cvss3 <= 6.9))

            if args.get("cvss").lower() == "high":
                query = query.filter(and_(Cve.cvss3 >= 7.0, Cve.cvss3 <= 8.9))

            if args.get("cvss").lower() == "critical":
                query = query.filter(and_(Cve.cvss3 >= 9.0, Cve.cvss3 <= 10.0))

        # Filter by vendor and product
        if args.get("vendor") and args.get("product"):
            vendor = Vendor.query.filter_by(name=args.get("vendor")).first()
            if not vendor:
                abort(404, "Not found.")

            product = Product.query.filter_by(
                name=args.get("product"), vendor_id=vendor.id
            ).first()
            if not product:
                abort(404, "Not found.")

            query = query.filter(
                Cve.vendors.contains(
                    [f"{vendor.name}{PRODUCT_SEPARATOR}{product.name}"]
                )
            )

        # Filter by vendor
        elif args.get("vendor"):
            vendor = Vendor.query.filter_by(name=args.get("vendor")).first()
            if not vendor:
                abort(404, "Not found.")
            query = query.filter(Cve.vendors.contains([vendor.name]))

        return query, {"vendor": vendor, "product": product}
