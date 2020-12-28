from opencve.extensions import db
from opencve.models import BaseModel


class Task(BaseModel):
    __tablename__ = "tasks"

    # Relationships
    changes = db.relationship("Change", back_populates="task")

    def __repr__(self):
        return "<Task {}>".format(self.created_at)
