from flask import Blueprint
from flask_restful import Api

from opencve.api.alerts import AlertListResource, AlertResource
from opencve.api.cves import CveListResource, CveResource
from opencve.api.cwes import CweListResource, CweResource, CweCveResource
from opencve.api.products import (
    ProductListResource,
    ProductResource,
    ProductCveResource,
)
from opencve.api.reports import ReportListResource, ReportResource
from opencve.api.vendors import VendorListResource, VendorResource, VendorCveResource

from opencve.api.subscriptions import (
    SubscriptionListRessourceVendor,
    SubscriptionListRessourceProduct,
)


api_bp = Blueprint("api", __name__)
api = Api(api_bp)


# Routes
api.add_resource(CweListResource, "/cwe")
api.add_resource(CweResource, "/cwe/<string:id>")
api.add_resource(CweCveResource, "/cwe/<string:id>/cve")
api.add_resource(CveListResource, "/cve")
api.add_resource(CveResource, "/cve/<string:id>")
api.add_resource(ReportListResource, "/reports")
api.add_resource(SubscriptionListRessourceVendor, "/account/subscriptions/vendors")
api.add_resource(SubscriptionListRessourceProduct, "/account/subscriptions/products")
api.add_resource(ReportResource, "/reports/<string:link>")
api.add_resource(AlertListResource, "/reports/<string:link>/alerts")
api.add_resource(AlertResource, "/reports/<string:link>/alerts/<string:id>")
api.add_resource(VendorListResource, "/vendors")
api.add_resource(VendorResource, "/vendors/<string:name>")
api.add_resource(VendorCveResource, "/vendors/<string:name>/cve")
api.add_resource(ProductListResource, "/vendors/<string:vendor>/products")
api.add_resource(ProductResource, "/vendors/<string:vendor>/products/<string:product>")
api.add_resource(
    ProductCveResource, "/vendors/<string:vendor>/products/<string:product>/cve"
)
