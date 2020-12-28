from sqlalchemy_utils import JSONType, UUIDType

from opencve.extensions import db
from opencve.models import BaseModel, alerts_events


class Alert(BaseModel):
    __tablename__ = "alerts"

    details = db.Column(JSONType)
    notify = db.Column(db.Boolean, default=False)

    # Relationships
    events = db.relationship("Event", secondary=alerts_events)

    user_id = db.Column(UUIDType(binary=False), db.ForeignKey("users.id"))
    user = db.relationship("User", back_populates="alerts")

    cve_id = db.Column(UUIDType(binary=False), db.ForeignKey("cves.id"))
    cve = db.relationship("Cve", back_populates="alerts")

    report_id = db.Column(
        UUIDType(binary=False), db.ForeignKey("reports.id"), nullable=True
    )
    report = db.relationship("Report", back_populates="alerts")

    def __repr__(self):
        return "<Alert {}>".format(self.id)
