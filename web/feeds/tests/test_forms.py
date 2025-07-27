from django.contrib.auth import get_user_model
from django.test import TestCase

from feeds.forms import FeedTokenForm
from feeds.models import FeedToken

User = get_user_model()


class FeedTokenFormTest(TestCase):
    """Tests for the FeedTokenForm."""

    def setUp(self):
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpassword"
        )

    def test_form_valid(self):
        """Test that the form is valid with correct data."""
        form = FeedTokenForm(
            {"name": "Test Token"},
            user=self.user
        )
        self.assertTrue(form.is_valid())

    def test_form_save(self):
        """Test that the form saves correctly."""
        form = FeedTokenForm(
            {"name": "Test Token"},
            user=self.user
        )
        self.assertTrue(form.is_valid())
        token = form.save()
        self.assertEqual(token.name, "Test Token")
        self.assertEqual(token.user, self.user)
        self.assertIsNotNone(token.token)

    def test_form_invalid_empty_name(self):
        """Test that the form is invalid with an empty name."""
        form = FeedTokenForm(
            {"name": ""},
            user=self.user
        )
        self.assertFalse(form.is_valid())
        self.assertIn("name", form.errors)