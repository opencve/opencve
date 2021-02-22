from flask import request, render_template

from opencve.controllers.main import main

# from opencve.controllers.cwes import get_cwes
from opencve.controllers.cwes import CweController


@main.route("/cwe")
def cwes():
    objects, _, pagination = CweController.list(request.args)
    return render_template("cwes.html", cwes=objects, pagination=pagination)
