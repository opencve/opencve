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
    title = models.TextField(default=None, null=True)
    description = models.TextField(default=None, null=True)
    vendors = models.JSONField(default=list)
    weaknesses = models.JSONField(default=list)
    metrics = models.JSONField(default=dict)

    # Raw Json data
    _kb_json = {}
    _mitre_json = {}
    _vulnrichment_json = {}
    _nvd_json = {}
    _redhat_json = {}

    class Meta:
        db_table = "opencve_cves"
        indexes = [
            GinIndex(name="ix_cves_vendors", fields=["vendors"]),
            GinIndex(name="ix_cves_metrics", fields=["metrics"]),
            GinIndex(name="ix_cves_weaknesses", fields=["weaknesses"]),
            GinIndex(
                OpClass(Upper("title"), name="gin_trgm_ops"),
                name="ix_cves_title",
            ),
            GinIndex(
                OpClass(Upper("description"), name="gin_trgm_ops"),
                name="ix_cves_description",
            ),
            GinIndex(
                OpClass(Upper("cve_id"), name="gin_trgm_ops"),
                name="ix_cves_cve_id",
            ),
        ]

    @property
    def kb_path(self):
        cve_path = f"{self.cve_id.split('-')[1]}/{self.cve_id}.json"
        return pathlib.Path(settings.KB_REPO_PATH) / cve_path

    @property
    def kb_json(self):
        if not self._kb_json:
            with open(self.kb_path) as f:
                self._kb_json = json.load(f)
        return self._kb_json

    @property
    def mitre_json(self):
        if not self._mitre_json:
            mitre_data = self.kb_json.get("mitre")
            if not mitre_data:
                self._mitre_json = {}
            else:
                mitre_path = (
                    pathlib.Path(settings.MITRE_REPO_PATH)
                    / mitre_data["mitre_repo_path"]
                )
                with open(mitre_path) as f:
                    self._mitre_json = json.load(f)
        return self._mitre_json

    @property
    def vulnrichment_json(self):
        if not self._vulnrichment_json:
            vulnrichment_data = self.kb_json.get("vulnrichment")
            if not vulnrichment_data:
                self._vulnrichment_json = {}
            else:
                vulnrichment_path = (
                    pathlib.Path(settings.VULNRICHMENT_REPO_PATH)
                    / vulnrichment_data["vulnrichment_repo_path"]
                )
                with open(vulnrichment_path) as f:
                    self._vulnrichment_json = json.load(f)
        return self._vulnrichment_json

    @property
    def nvd_json(self):
        if not self._nvd_json:
            nvd_data = self.kb_json.get("nvd")
            if not nvd_data:
                self._nvd_json = {}
            else:
                nvd_path = (
                    pathlib.Path(settings.NVD_REPO_PATH) / nvd_data["nvd_repo_path"]
                )
                with open(nvd_path) as f:
                    self._nvd_json = json.load(f)
        return self._nvd_json

    @property
    def redhat_json(self):
        if not self._redhat_json:
            redhat_data = self.kb_json.get("redhat")
            if not redhat_data:
                self._redhat_json = {}
            else:
                redhat_path = (
                    pathlib.Path(settings.REDHAT_REPO_PATH)
                    / redhat_data["redhat_repo_path"]
                )
                with open(redhat_path) as f:
                    self._redhat_json = json.load(f)
        return self._redhat_json

    @property
    def cvssV2_0(self):
        return self.metrics.get("cvssV2_0", {}).get("data", {})

    @property
    def cvssV3_0(self):
        return self.metrics.get("cvssV3_0", {}).get("data", {})

    @property
    def cvssV3_1(self):
        return self.metrics.get("cvssV3_1", {}).get("data", {})

    @property
    def cvssV4_0(self):
        return self.metrics.get("cvssV4_0", {}).get("data", {})

    @property
    def kev(self):
        return self.metrics.get("kev")

    @property
    def ssvc(self):
        return self.metrics.get("ssvc")

    @property
    def references(self):
        return self.kb_json["opencve"]["references"]

    def __str__(self):
        return self.cve_id


class Weakness(BaseModel):
    cwe_id = models.CharField(max_length=16, unique=True)
    name = models.CharField(max_length=256, blank=True, null=True)
    description = models.TextField(blank=True, null=True)

    class Meta:
        db_table = "opencve_weaknesses"

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


class Variable(BaseModel):
    name = models.CharField(max_length=256, unique=True)
    value = models.JSONField(default=dict)

    class Meta:
        db_table = "opencve_variables"
