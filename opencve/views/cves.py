import itertools
import json
import operator

from flask import abort, flash, redirect, request, render_template, url_for
from flask_user import current_user, login_required

from opencve.controllers.cves import CveController
from opencve.controllers.main import main
from opencve.controllers.tags import UserTagController
from opencve.extensions import db
from opencve.models import is_valid_uuid
from opencve.models.changes import Change
from opencve.models.events import Event
from opencve.models.tags import CveTag
from opencve.utils import convert_cpes, get_cwes_details, CustomHtmlHTML


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

    events = Event.query.filter_by(cve_id=cve.id).order_by(Event.created_at.desc())

    events_by_time = [
        (time, list(evs))
        for time, evs in (itertools.groupby(events, operator.attrgetter("created_at")))
    ]

    return render_template(
        "cve.html",
        cve=cve,
        cve_dumped=json.dumps(cve.json),
        vendors=vendors,
        cwes=cwes,
        user_tags=user_tags,
        cve_tags_encoded=cve_tags_encoded,
        events_by_time=events_by_time,
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


@main.route("/cve/<cve_id>/changes/<change_id>")
def cve_change(cve_id, change_id):
    cve = CveController.get({"cve_id": cve_id})

    if not is_valid_uuid(change_id):
        abort(404)

    change = Change.query.filter_by(cve_id=cve.id, id=change_id).first()
    if not change:
        abort(404)

    previous = (
        Change.query.filter(Change.created_at < change.created_at)
        .filter(Change.cve == change.cve)
        .order_by(Change.created_at.desc())
        .first()
    )

    previous_json = {}
    if previous:
        previous_json = previous.json

    differ = CustomHtmlHTML()
    diff = differ.make_table(
        fromlines=json.dumps(previous_json, sort_keys=True, indent=2).split("\n"),
        tolines=json.dumps(change.json, sort_keys=True, indent=2).split("\n"),
        context=True,
    )

    return render_template("change.html", change=change, diff=diff)
