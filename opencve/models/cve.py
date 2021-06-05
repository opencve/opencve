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
