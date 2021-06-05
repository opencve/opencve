import json

from flask import current_app as app
from flask import abort, redirect, render_template, request, url_for
from flask_paginate import Pagination
from sqlalchemy import and_, or_

from opencve.constants import PRODUCT_SEPARATOR
from opencve.controllers.base import BaseController
from opencve.controllers.main import main
from opencve.controllers.tags import UserTagController
from opencve.models.cve import Cve
from opencve.models.products import Product
from opencve.models.tags import CveTag
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
        "tag": {"type": str},
        "user_id": {"type": str},
    }

    @classmethod
    def build_query(cls, args):
        vendor = None
        product = None
        tag = None
        query = Cve.query

        vendor_query = args.get("vendor")
        product_query = args.get("product")

        if vendor_query:
            vendor_query = vendor_query.replace(" ", "").lower()

        if product_query:
            product_query = product_query.replace(" ", "_").lower()

        # Filter by keyword
        if args.get("search"):

            possible_vendor = args.get("search").replace(" ", "").lower()
            possible_product = args.get("search").replace(" ", "_").lower()

            vendor = Vendor.query.filter_by(name=possible_vendor).first()

            if vendor:
                product = Product.query.filter_by(
                    name=possible_product, vendor_id=vendor.id
                ).first()
            else:
                product = Product.query.filter_by(name=possible_product).first()

            query = query.filter(
                or_(
                    Cve.cve_id.contains(args.get("search")),
                    Cve.summary.ilike(f"%{args.get('search')}%"),
                    Cve.vendors.contains([vendor.name]) if vendor else None,
                    Cve.vendors.contains([product.name]) if product else None,
                )
            )

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
        if vendor_query and product_query:
            vendor = Vendor.query.filter_by(name=vendor_query).first()
            if not vendor:
                abort(404, "Not found.")

            product = Product.query.filter_by(
                name=product_query, vendor_id=vendor.id
            ).first()
            if not product:
                abort(404, "Not found.")

            query = query.filter(
                Cve.vendors.contains(
                    [f"{vendor.name}{PRODUCT_SEPARATOR}{product.name}"]
                )
            )

        # Filter by vendor
        elif vendor_query:
            vendor = Vendor.query.filter_by(name=vendor_query).first()
            if not vendor:
                abort(404, "Not found.")
            query = query.filter(Cve.vendors.contains([vendor.name]))

        # Filter by product only
        elif product_query:
            product = Product.query.filter_by(name=product_query).first()
            if not product:
                abort(404, "Not found.")
            query = query.filter(Cve.vendors.contains([product.name]))

        # Filter by tag
        if args.get("tag"):
            tag = UserTagController.get(
                {"user_id": args.get("user_id"), "name": args.get("tag")}
            )
            if not tag:
                abort(404, "Not found.")
            query = (
                query.join(CveTag)
                .filter(CveTag.user_id == args.get("user_id"))
                .filter(CveTag.tags.contains([args.get("tag")]))
            )

        return query, {"vendor": vendor, "product": product, "tag": tag}
