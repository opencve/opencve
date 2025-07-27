import secrets
import string
from django.db import models
from django.utils import timezone

from opencve.models import BaseModel
from users.models import User


def generate_token():
    """Generate a random token for feed authentication."""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(64))


class FeedToken(BaseModel):
    """Model to store feed tokens for users."""
    token = models.CharField(max_length=64, unique=True, default=generate_token)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="feed_tokens")
    name = models.CharField(max_length=100)  # For user to identify different tokens
    last_used = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = "opencve_feed_tokens"
        
    def __str__(self):
        return f"{self.name} ({self.user.username})"