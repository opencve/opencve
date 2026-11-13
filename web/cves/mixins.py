from cves.constants import CVE_DEFAULT_ORDERING, CVE_ORDERINGS
from cves.utils import cve_ordering_fields


class CveOrderingMixin:
    """
    Order a list of CVEs using the `ordering` query parameter.

    Unknown values are ignored and the default ordering is used instead.
    """

    def get_cve_ordering(self):
        ordering = self.request.GET.get("ordering")
        if ordering not in CVE_ORDERINGS:
            return CVE_DEFAULT_ORDERING
        return ordering

    def order_cves(self, queryset):
        return queryset.order_by(*cve_ordering_fields(self.get_cve_ordering()))

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["cve_orderings"] = CVE_ORDERINGS
        context["cve_ordering"] = self.get_cve_ordering()
        return context
