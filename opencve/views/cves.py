import json

from flask import abort, flash, redirect, request, render_template, url_for
from flask_user import current_user, login_required

from opencve.controllers.cves import CveController
from opencve.controllers.main import main
from opencve.controllers.tags import UserTagController
from opencve.extensions import db
from opencve.models.tags import CveTag
from opencve.utils import convert_cpes, get_cwes_details


@main.route("/cve")
def cves():
    args = request.args
    user_tags = []
    if current_user.is_authenticated:
        args = {**request.args, "user_id": current_user.id}
        user_tags = UserTagController.list_items({"user_id": current_user.id})

    objects, metas, pagination = CveController.list(args)

    return render_template(
        "cves.html",
        cves=objects,
        vendor=metas.get("vendor"),
        product=metas.get("product"),
        tag=metas.get("tag"),
        user_tags=user_tags,
        pagination=pagination,
    )


@main.route("/cve/<cve_id>")
def cve(cve_id):
    cve = CveController.get({"cve_id": cve_id})

    vendors = convert_cpes(cve.json["configurations"])
    cwes = get_cwes_details(
        cve.json["cve"]["problemtype"]["problemtype_data"][0]["description"]
    )

    # Get the user tags
    user_tags = []
    if current_user.is_authenticated:
        user_tags = UserTagController.list_items({"user_id": current_user.id})

    # We have to pass an encoded list of tags for the modal box
    cve_tags_encoded = json.dumps([t.name for t in cve.tags])

    return render_template(
        "cve.html",
        cve=cve,
        cve_dumped=json.dumps(cve.json),
        vendors=vendors,
        cwes=cwes,
        user_tags=user_tags,
        cve_tags_encoded=cve_tags_encoded,
    )


@main.route("/cve/<cve_id>/tags", methods=["POST"])
@login_required
def cve_associate_tags(cve_id):
    cve = CveController.get({"cve_id": cve_id})
    new_tags = request.form.getlist("tags")

    # Check if all tags are declared by the user
    user_tags = [
        t.name for t in UserTagController.list_items({"user_id": current_user.id})
    ]
    for new_tag in new_tags:
        if new_tag not in user_tags:
            abort(404)

    # Update the CVE tags
    cve_tag = CveTag.query.filter_by(user_id=current_user.id, cve_id=cve.id).first()

    if not cve_tag:
        cve_tag = CveTag(user_id=current_user.id, cve_id=cve.id)

    cve_tag.tags = new_tags
    db.session.add(cve_tag)
    db.session.commit()

    flash("The CVE tags have been updated.", "success")
    return redirect(url_for("main.cve", cve_id=cve_id))
