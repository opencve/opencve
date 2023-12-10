from sqlalchemy.dialects.postgresql import JSONB
from flask_user import current_user

from opencve.extensions import db
from opencve.models import BaseModel
from opencve.models.tags import CveTag, UserTag


class Cve(BaseModel):
    __tablename__ = "cves"

    # CVE are sorted by last modified date, we need to index it.
    updated_at = db.Column(
        db.DateTime(timezone=True),
        default=db.func.now(),
        onupdate=db.func.now(),
        nullable=False,
        index=True,
    )

    cve_id = db.Column(db.String(), nullable=False)
    json = db.Column(JSONB)

    # We used initially secondary relationships to fetch the list of
    # associated vendors, products and cwes. But it was complicated
    # to maintain, and the performance were poor. So we now use the
    # JSONB data type associated to the GIN index type.
    vendors = db.Column(JSONB)
    cwes = db.Column(JSONB)

    # Keep the summary separated when searching keywords
    summary = db.Column(db.String(), nullable=False)

    # Keep CVSS separated when searching a particupal score
    cvss2 = db.Column(db.Float())
    cvss3 = db.Column(db.Float())

    # Relationships
    events = db.relationship("Event", back_populates="cve")
    changes = db.relationship("Change", back_populates="cve")
    alerts = db.relationship("Alert", back_populates="cve")

    # Index
    __table_args__ = (
        db.Index("ix_cves_vendors", vendors, postgresql_using="gin"),
        db.Index("ix_cves_cwes", cwes, postgresql_using="gin"),
        db.Index(
            "ix_cves_summary",
            summary,
            postgresql_using="gin",
            postgresql_ops={
                "summary": "gin_trgm_ops",
            },
        ),
        db.Index(
            "ix_cves_cve_id",
            cve_id,
            postgresql_using="gin",
            postgresql_ops={
                "cve_id": "gin_trgm_ops",
            },
        ),
    )

    def __repr__(self):
        return "<Cve {}>".format(self.cve_id)

    @property
    def raw_tags(self):
        if not current_user.is_authenticated:
            return []

        cve_tag = CveTag.query.filter_by(
            user_id=current_user.id, cve_id=self.id
        ).first()
        if not cve_tag:
            return []

        return cve_tag.tags

    @property
    def tags(self):
        if not current_user.is_authenticated:
            return []
        return [
            UserTag.query.filter_by(user_id=current_user.id, name=t).first()
            for t in self.raw_tags
        ]

    @property
    def cvss_weight(self):
        """Only used to sort several CVE by their CVSS"""
        w = 0
        if self.cvss2:
            w += self.cvss2
        if self.cvss3:
            w += self.cvss3
        return w

    @property
    def cvss2_score(self):
        if "cve" in self.json.keys():
            if "baseMetricV2" in self.json["impact"]:
                return self.json["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
        else:
            if "cvssMetricV2" in self.json["metrics"]:
                return self.json["metrics"]["cvssMetricV2"][0]["cvssData"]["baseScore"]

        return None

    @property
    def cvss3_score(self):
        if "cve" in self.json.keys():
            if "baseMetricV3" in self.json["impact"]:
                return self.json["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
        else:
            if "cvssMetricV31" in self.json["metrics"]:
                return self.json["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV30" in self.json["metrics"]:
                return self.json["metrics"]["cvssMetricV30"][0]["cvssData"]["baseScore"]

        return None

    @property
    def cvss2_severity(self):
        if "cve" in self.json.keys():
            if "baseMetricV2" in self.json["impact"]:
                return self.json["impact"]["baseMetricV2"]["severity"]
        else:
            if "cvssMetricV2" in self.json["metrics"]:
                return self.json["metrics"]["cvssMetricV2"][0]["baseSeverity"]

        return None

    @property
    def cvss3_severity(self):
        if "cve" in self.json.keys():
            if "baseMetricV3" in self.json["impact"]:
                return self.json["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
        else:
            if "cvssMetricV31" in self.json["metrics"]:
                return self.json["metrics"]["cvssMetricV31"][0]["cvssData"][
                    "baseSeverity"
                ]
            elif "cvssMetricV30" in self.json["metrics"]:
                return self.json["metrics"]["cvssMetricV30"][0]["cvssData"][
                    "baseSeverity"
                ]

        return None

    @property
    def references(self):
        if "cve" in self.json.keys():
            return self.json["cve"]["references"]["reference_data"]
        return self.json["references"]
