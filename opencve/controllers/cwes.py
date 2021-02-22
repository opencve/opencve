import string

from flask import abort

from opencve.controllers.base import BaseController
from opencve.models.cve import Cve
from opencve.models.cwe import Cwe


class CweController(BaseController):
    model = Cwe
    order = Cwe.cwe_id.desc()
    per_page_param = "CWES_PER_PAGE"
    schema = {
        "search": {"type": str},
    }

    @classmethod
    def build_query(cls, args):
        query = cls.model.query

        # Filter the list of CWE
        if args.get("search"):
            search = args.get("search").strip().lower()

            # By ID or by string
            search = search[4:] if search.startswith("cwe-") else search
            try:
                search = int(search)
                query = query.filter_by(cwe_id=f"CWE-{search}")
            except ValueError:
                query = query.filter(Cwe.name.ilike("%{}%".format(search)))

        return query, {}
