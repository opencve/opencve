from opencve.extensions import db
from opencve.models import BaseModel


class Meta(BaseModel):
    __tablename__ = "metas"

    name = db.Column(db.String(), nullable=False)
    value = db.Column(db.String(), nullable=False)

    def __repr__(self):
        return "<Meta {}>".format(self.name)
