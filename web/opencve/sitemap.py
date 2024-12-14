from django.conf import settings
from django.contrib.sitemaps import Sitemap
from django.urls import reverse

from cves.models import Cve, Product, Vendor, Weakness


class CustomSitemap(Sitemap):
    changefreq = "daily"
    priority = 1
    limit = 2000
    protocol = "http" if settings.DEBUG else "https"
    queryset = None

    def items(self):
        return self.queryset


class CveSitemap(CustomSitemap):
    queryset = Cve.objects.order_by("created_at").values("cve_id", "updated_at")

    def lastmod(self, obj):
        return obj["updated_at"]

    def location(self, item):
        return reverse("cve", kwargs={"cve_id": item["cve_id"]})


class VendorSitemap(CustomSitemap):
    queryset = Vendor.objects.order_by("created_at").values("name")

    def location(self, item):
        return f"{reverse('cves')}?vendor={item['name']}"


class ProductSitemap(CustomSitemap):
    queryset = (
        Product.objects.order_by("created_at")
        .exclude(name="")
        .values("name", "vendor__name")
    )

    def location(self, item):
        return f"{reverse('cves')}?vendor={item['vendor__name']}&product={item['name']}"


class WeaknessSitemap(CustomSitemap):
    queryset = Weakness.objects.order_by("created_at").values("cwe_id")

    def location(self, item):
        return f"{reverse('cves')}?weakness={item['cwe_id']}"


class StaticSitemap(CustomSitemap):
    def items(self):
        return ["cves", "vendors", "weaknesses"]

    def location(self, item):
        return reverse(item)


sitemaps = {
    "cves": CveSitemap,
    "vendors": VendorSitemap,
    "products": ProductSitemap,
    "weaknesses": WeaknessSitemap,
    "static": StaticSitemap,
}
