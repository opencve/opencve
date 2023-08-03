import json
import pathlib

from django.conf import settings
from django.contrib.postgres.indexes import GinIndex, OpClass
from django.db import models
from django.db.models.functions import Upper

from cves.constants import PRODUCT_SEPARATOR
from cves.utils import humanize
from opencve.models import BaseModel


class Cve(BaseModel):
    cve_id = models.CharField(max_length=20, unique=True)
    vendors = models.JSONField(default=list)
    cwes = models.JSONField(default=list)
    sources = models.JSONField(default=dict)

    # Keep the summary separated when searching keywords
    summary = models.TextField(default=None, null=True)

    # Keep CVSS separated when searching CVEs by score
    cvss = models.JSONField(default=dict)

    # Raw Json data
    _mitre_json = None
    _nvd_json = None

    class Meta:
        db_table = "opencve_cves"
        indexes = [
            GinIndex(name="ix_cves_vendors", fields=["vendors"]),
            GinIndex(name="ix_cves_cwes", fields=["cwes"]),
            GinIndex(
                OpClass(Upper("summary"), name="gin_trgm_ops"),
                name="ix_cves_summary",
            ),
            GinIndex(
                OpClass(Upper("cve_id"), name="gin_trgm_ops"),
                name="ix_cves_cve_id",
            ),
        ]

    @property
    def mitre_json(self):
        if not self._mitre_json:
            if "mitre" in self.sources:
                path = pathlib.Path(settings.MITRE_REPO_PATH) / self.sources.get("mitre")
                with open(path) as f:
                    self._mitre_json = json.load(f)
            else:
                self._mitre_json = {}
        return self._mitre_json

    @property
    def nvd_json(self):
        if not self._nvd_json:
            if "nvd" in self.sources:
                path = pathlib.Path(settings.NVD_REPO_PATH) / self.sources.get("nvd")
                with open(path) as f:
                    self._nvd_json = json.load(f)
            else:
                self._nvd_json = {}
        return self._nvd_json

    @property
    def cvss20(self):
        return self.cvss.get("v20")

    @property
    def cvss30(self):
        return self.cvss.get("v30")

    @property
    def cvss31(self):
        return self.cvss.get("v31")

    def __str__(self):
        return self.cve_id


class Cwe(BaseModel):
    cwe_id = models.CharField(max_length=16, unique=True)
    name = models.CharField(max_length=256, blank=True, null=True)
    description = models.TextField(blank=True, null=True)

    class Meta:
        db_table = "opencve_cwes"

    @property
    def short_id(self):
        if not self.cwe_id.startswith("CWE-"):
            return None
        return self.cwe_id.split("CWE-")[1]

    def __str__(self):
        return self.cwe_id


class Vendor(BaseModel):
    name = models.CharField(max_length=256, unique=True)

    class Meta:
        db_table = "opencve_vendors"

    @property
    def human_name(self):
        return humanize(self.name)

    def __str__(self):
        return self.name


class Product(BaseModel):
    name = models.CharField(max_length=256)
    vendor = models.ForeignKey(
        Vendor, on_delete=models.CASCADE, related_name="products"
    )

    class Meta:
        db_table = "opencve_products"
        constraints = [
            models.UniqueConstraint(
                fields=["name", "vendor_id"], name="ix_unique_products"
            )
        ]

    @property
    def human_name(self):
        return humanize(self.name)

    @property
    def vendored_name(self):
        return f"{self.vendor.name}{PRODUCT_SEPARATOR}{self.name}"

    def __str__(self):
        return self.name
