from sqlalchemy_utils import UUIDType

from opencve.extensions import db
from opencve.models import BaseModel


class Epss(BaseModel):
    __tablename__ = "epss_scores"

    cve_uuid = db.Column(UUIDType(binary=False), db.ForeignKey('cves.id'), nullable=False, index=True)
    cve_id = db.Column(db.String(), nullable=False, index=True)
    score = db.Column(db.Float(), nullable=False)
    percentile = db.Column(db.Float(), nullable=False)

    # Relationship to CVE based on cve_id
    cve = db.relationship('Cve', back_populates="epss")

    def __repr__(self):
        return "<Epss for CVE UUID: {}, Score: {}>".format(self.cve_uuid, self.score)
