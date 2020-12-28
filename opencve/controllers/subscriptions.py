import json

from flask import request
from flask_user import current_user, login_required

from opencve.controllers.main import main
from opencve.extensions import db
from opencve.models.products import Product
from opencve.models.vendors import Vendor


@main.route("/subscriptions", methods=["POST"])
@login_required
def subscribe_to_tag():
    if not current_user.is_authenticated:
        return json.dumps({"status": "error", "message": "not allowed"})

    # Check the required fields
    if not request.form["obj"] or not request.form["id"]:
        return json.dumps({"status": "error", "message": "bad request"})

    if not request.form["action"] or request.form["action"] not in [
        "subscribe",
        "unsubscribe",
    ]:
        return json.dumps({"status": "error", "message": "bad request"})

    # Vendor
    if request.form["obj"] == "vendor":
        vendor = Vendor.query.get(request.form["id"])

        # Subscribe
        if request.form["action"] == "subscribe":
            if vendor not in current_user.vendors:
                current_user.vendors.append(vendor)
                db.session.commit()

            return json.dumps({"status": "ok", "message": "vendor added"})

        # Unsubscribe
        if request.form["action"] == "unsubscribe":
            if vendor in current_user.vendors:
                current_user.vendors.remove(vendor)
                db.session.commit()

            return json.dumps({"status": "ok", "message": "vendor removed"})

    # Product
    elif request.form["obj"] == "product":
        product = Product.query.get(request.form["id"])

        # Subscribe
        if request.form["action"] == "subscribe":
            if product not in current_user.products:
                current_user.products.append(product)
                db.session.commit()

            return json.dumps({"status": "ok", "message": "product added"})

        # Unsubscribe
        if request.form["action"] == "unsubscribe":
            if product in current_user.products:
                current_user.products.remove(product)
                db.session.commit()

            return json.dumps({"status": "ok", "message": "product removed"})

    return json.dumps({"status": "error", "message": "bad request"})
