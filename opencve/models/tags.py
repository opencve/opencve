from sqlalchemy_utils import UUIDType
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.schema import UniqueConstraint

from opencve.extensions import db
from opencve.models import BaseModel, alerts_events


class UserTag(BaseModel):
    __tablename__ = "users_tags"

    name = db.Column(db.String(), nullable=False)
    description = db.Column(db.String())
    color = db.Column(db.String(), nullable=False)

    # Relationships
    user_id = db.Column(
        UUIDType(binary=False), db.ForeignKey("users.id"), nullable=False
    )
    user = db.relationship("User", back_populates="tags")

    __table_args__ = (
        UniqueConstraint("name", "user_id", name="ix_userstags_name_userid"),
    )

    def __repr__(self):
        return "<UserTag {}>".format(self.id)


class CveTag(BaseModel):
    __tablename__ = "cves_tags"

    tags = db.Column(JSONB)

    # Relationships
    user_id = db.Column(UUIDType(binary=False), db.ForeignKey("users.id"))
    user = db.relationship("User", back_populates="cve_tags")

    cve_id = db.Column(UUIDType(binary=False), db.ForeignKey("cves.id"))

    # Index
    __table_args__ = (db.Index("ix_cves_tags", tags, postgresql_using="gin"),)

    def __repr__(self):
        return "<CveTag {}>".format(self.id)
