import json

from flask import abort, request, render_template

from opencve.controllers.cves import CveController
from opencve.controllers.main import main
from opencve.utils import convert_cpes, get_cwes_details


@main.route("/cve")
def cves():
    objects, metas, pagination = CveController.list(request.args)
    return render_template(
        "cves.html",
        cves=objects,
        vendor=metas.get("vendor"),
        product=metas.get("product"),
        pagination=pagination,
    )


@main.route("/cve/<cve_id>")
def cve(cve_id):
    cve = CveController.get({"cve_id": cve_id})

    vendors = convert_cpes(cve.json["configurations"])
    cwes = get_cwes_details(
        cve.json["cve"]["problemtype"]["problemtype_data"][0]["description"]
    )

    return render_template(
        "cve.html", cve=cve, cve_dumped=json.dumps(cve.json), vendors=vendors, cwes=cwes
    )
