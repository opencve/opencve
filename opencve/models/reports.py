import random
import string

from sqlalchemy_utils import JSONType, UUIDType

from opencve.extensions import db
from opencve.models import BaseModel


def generate_public_link(size=12):
    chars = string.ascii_uppercase + string.digits
    return "".join(random.choice(chars) for _ in range(size))


class Report(BaseModel):
    __tablename__ = "reports"

    public_link = db.Column(db.String(), default=generate_public_link)
    seen = db.Column(db.Boolean(), default=False)
    details = db.Column(JSONType)

    user_id = db.Column(UUIDType(binary=False), db.ForeignKey("users.id"))
    user = db.relationship("User", back_populates="reports")

    alerts = db.relationship("Alert", back_populates="report")

    def __repr__(self):
        return "<Report {}>".format(self.id)
