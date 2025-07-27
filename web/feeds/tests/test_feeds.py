import uuid
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase, Client
from django.urls import reverse
from django.utils import timezone

from changes.models import Change
from cves.models import Cve
from feeds.models import FeedToken
from organizations.models import Organization, Membership
from projects.models import Project

User = get_user_model()


class FeedTokenModelTest(TestCase):
    """Tests for the FeedToken model."""

    def setUp(self):
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpassword"
        )

    def test_token_generation(self):
        """Test that tokens are automatically generated."""
        token = FeedToken.objects.create(
            user=self.user,
            name="Test Token"
        )
        self.assertIsNotNone(token.token)
        self.assertEqual(len(token.token), 64)

    def test_token_uniqueness(self):
        """Test that tokens are unique."""
        token1 = FeedToken.objects.create(
            user=self.user,
            name="Token 1"
        )
        token2 = FeedToken.objects.create(
            user=self.user,
            name="Token 2"
        )
        self.assertNotEqual(token1.token, token2.token)

    def test_token_str_representation(self):
        """Test the string representation of a token."""
        token = FeedToken.objects.create(
            user=self.user,
            name="Test Token"
        )
        self.assertEqual(str(token), f"Test Token ({self.user.username})")


class FeedTokenViewsTest(TestCase):
    """Tests for the feed token management views."""

    def setUp(self):
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpassword"
        )
        self.client = Client()
        self.client.login(username="testuser", password="testpassword")

    def test_token_list_view(self):
        """Test the token list view."""
        FeedToken.objects.create(
            user=self.user,
            name="Test Token"
        )
        response = self.client.get(reverse("feeds:feed_tokens"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Test Token")

    def test_token_create_view(self):
        """Test creating a new token."""
        response = self.client.post(
            reverse("feeds:create_token"),
            {"name": "New Token"}
        )
        self.assertEqual(response.status_code, 302)  # Redirect after successful creation
        self.assertTrue(FeedToken.objects.filter(name="New Token").exists())

    def test_token_delete_view(self):
        """Test deleting a token."""
        token = FeedToken.objects.create(
            user=self.user,
            name="Test Token"
        )
        response = self.client.post(
            reverse("feeds:delete_token", kwargs={"token_id": token.id})
        )
        self.assertEqual(response.status_code, 302)  # Redirect after successful deletion
        self.assertFalse(FeedToken.objects.filter(id=token.id).exists())


class FeedAuthenticationTest(TestCase):
    """Tests for the feed authentication mechanism."""

    def setUp(self):
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpassword"
        )
        self.token = FeedToken.objects.create(
            user=self.user,
            name="Test Token"
        )
        self.client = Client()

    def test_valid_token_authentication(self):
        """Test accessing a feed with a valid token."""
        response = self.client.get(
            reverse("feeds:user_feed", kwargs={"token": self.token.token})
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "application/rss+xml")

    def test_invalid_token_authentication(self):
        """Test accessing a feed with an invalid token."""
        response = self.client.get(
            reverse("feeds:user_feed", kwargs={"token": "invalid-token"})
        )
        self.assertEqual(response.status_code, 404)

    def test_token_last_used_update(self):
        """Test that the last_used timestamp is updated when a feed is accessed."""
        # Set the last_used to a known value
        self.token.last_used = timezone.now() - timedelta(days=1)
        self.token.save()

        # Access the feed
        self.client.get(
            reverse("feeds:user_feed", kwargs={"token": self.token.token})
        )

        # Refresh the token from the database
        self.token.refresh_from_db()

        # Check that the last_used timestamp has been updated
        self.assertGreater(
            self.token.last_used,
            timezone.now() - timedelta(minutes=1)
        )


class FeedContentTest(TestCase):
    """Tests for the content of the feeds."""

    def setUp(self):
        # Create a user
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpassword"
        )
        self.token = FeedToken.objects.create(
            user=self.user,
            name="Test Token"
        )

        # Create an organization
        self.organization = Organization.objects.create(
            name="testorg"
        )
        Membership.objects.create(
            user=self.user,
            organization=self.organization,
            role=Membership.OWNER,
            date_joined=timezone.now()
        )

        # Create a project
        self.project = Project.objects.create(
            name="testproject",
            organization=self.organization,
            subscriptions={
                "vendors": ["test_vendor"],
                "products": []
            }
        )

        # Create a CVE
        self.cve = Cve.objects.create(
            cve_id="CVE-2023-12345",
            description="Test CVE",
            vendors=["test_vendor"]
        )

        # Create a change
        self.change = Change.objects.create(
            cve=self.cve,
            path="test/path",
            commit="testcommit",
            types=["test_type"]
        )

        self.client = Client()

    def test_user_feed_content(self):
        """Test the content of the user feed."""
        response = self.client.get(
            reverse("feeds:user_feed", kwargs={"token": self.token.token})
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "CVE-2023-12345")
        self.assertContains(response, "Test CVE")

    def test_project_feed_content(self):
        """Test the content of the project feed."""
        response = self.client.get(
            reverse("feeds:project_feed", kwargs={
                "token": self.token.token,
                "org_name": self.organization.name,
                "project_name": self.project.name
            })
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "CVE-2023-12345")
        self.assertContains(response, "Test CVE")

    def test_feed_item_count(self):
        """Test that the feed contains the correct number of items."""
        # Create 35 more changes (for a total of 36)
        for i in range(35):
            Change.objects.create(
                cve=self.cve,
                path=f"test/path/{i}",
                commit=f"testcommit{i}",
                types=[f"test_type{i}"]
            )

        # The feed should only contain the 30 most recent changes
        response = self.client.get(
            reverse("feeds:user_feed", kwargs={"token": self.token.token})
        )
        self.assertEqual(response.status_code, 200)

        # Count the number of <item> elements in the response
        item_count = response.content.decode().count("<item>")
        self.assertEqual(item_count, 30)