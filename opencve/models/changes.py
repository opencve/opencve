from sqlalchemy_utils import JSONType, UUIDType

from opencve.extensions import db
from opencve.models import BaseModel


class Change(BaseModel):
    __tablename__ = "changes"

    json = db.Column(JSONType)

    # Relationships
    cve_id = db.Column(UUIDType(binary=False), db.ForeignKey("cves.id"))
    cve = db.relationship("Cve", back_populates="changes")

    task_id = db.Column(UUIDType(binary=False), db.ForeignKey("tasks.id"))
    task = db.relationship("Task", back_populates="changes")

    events = db.relationship("Event", back_populates="change")
