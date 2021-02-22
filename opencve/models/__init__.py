import uuid

from sqlalchemy_utils import UUIDType

from opencve.extensions import db


def get_uuid():
    return str(uuid.uuid4())


def is_valid_uuid(val):
    """Check if a given value is a valid UUID"""
    try:
        uuid.UUID(str(val))
    except ValueError:
        return False
    return True


class BaseModel(db.Model):
    __abstract__ = True

    id = db.Column(
        UUIDType(binary=False), primary_key=True, nullable=False, default=get_uuid
    )
    created_at = db.Column(
        db.DateTime(timezone=True), default=db.func.now(), nullable=False, index=True
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        default=db.func.now(),
        onupdate=db.func.now(),
        nullable=False,
    )

    def to_dict(self, attrs):
        return {attr: str(getattr(self, attr)) for attr in attrs}

    def __repr__(self):
        return """<{} '{}'>""".format(self.__class__.__name__, self.id)


users_vendors = db.Table(
    "users_vendors",
    db.Column(
        "user_id", UUIDType(binary=False), db.ForeignKey("users.id"), primary_key=True
    ),
    db.Column(
        "vendor_id",
        UUIDType(binary=False),
        db.ForeignKey("vendors.id"),
        primary_key=True,
    ),
)

users_products = db.Table(
    "users_products",
    db.Column(
        "user_id", UUIDType(binary=False), db.ForeignKey("users.id"), primary_key=True
    ),
    db.Column(
        "product_id",
        UUIDType(binary=False),
        db.ForeignKey("products.id"),
        primary_key=True,
    ),
)

alerts_events = db.Table(
    "alerts_events",
    db.Column(
        "alert_id", UUIDType(binary=False), db.ForeignKey("alerts.id"), primary_key=True
    ),
    db.Column(
        "event_id", UUIDType(binary=False), db.ForeignKey("events.id"), primary_key=True
    ),
)
