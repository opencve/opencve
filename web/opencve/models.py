import uuid

from django.db import models
from django.db.models import signals
from django.utils import timezone


class BaseModel(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    updated_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        abstract = True

    def to_dict(self, attrs):
        return {attr: str(getattr(self, attr)) for attr in attrs}

    def __str__(self):
        return str(self.id)


# Update the update_at field at each change
def _pre_save(instance, **kwargs):
    instance.updated_at = timezone.now()


signals.pre_save.connect(_pre_save)
