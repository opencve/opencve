from sqlalchemy_utils import UUIDType

from opencve.extensions import db
from opencve.models import BaseModel, users_products


class Product(BaseModel):
    __tablename__ = "products"

    name = db.Column(db.String(), nullable=False, index=True)

    # Relationships
    vendor_id = db.Column(UUIDType(binary=False), db.ForeignKey("vendors.id"))
    vendor = db.relationship("Vendor", back_populates="products")
    users = db.relationship("User", secondary=users_products)

    def __repr__(self):
        return "<Product {}>".format(self.name)
