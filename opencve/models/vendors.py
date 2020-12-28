from opencve.extensions import db
from opencve.models import BaseModel, users_vendors


class Vendor(BaseModel):
    __tablename__ = "vendors"

    name = db.Column(db.String(), nullable=False, unique=True)

    # Relationships
    products = db.relationship("Product", back_populates="vendor")
    users = db.relationship("User", secondary=users_vendors)

    def __repr__(self):
        return "<Vendor {}>".format(self.name)
