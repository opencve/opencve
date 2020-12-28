from sqlalchemy_utils import ChoiceType, JSONType, UUIDType

from opencve.constants import EVENT_TYPES
from opencve.extensions import db
from opencve.models import BaseModel, alerts_events


class Event(BaseModel):
    __tablename__ = "events"

    type = db.Column(ChoiceType(EVENT_TYPES))
    details = db.Column(JSONType)
    review = db.Column(db.Boolean, default=False)

    # Relationships
    cve_id = db.Column(UUIDType(binary=False), db.ForeignKey("cves.id"))
    cve = db.relationship("Cve", back_populates="events")
    change_id = db.Column(UUIDType(binary=False), db.ForeignKey("changes.id"))
    change = db.relationship("Change", back_populates="events")
    alerts = db.relationship("Alert", secondary=alerts_events)

    def __repr__(self):
        return "<Event {}>".format(self.type)
