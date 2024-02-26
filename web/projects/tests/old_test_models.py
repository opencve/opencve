from django.test import TestCase

from projects.models import Project
from users.models import User


class CveViewTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        user = User.objects.create_user(username="user1", password="password")
        Project.objects.create(name="foo", user=user)

    def test_absolute_url(self):
        project = Project.objects.first()
        self.assertEqual(project.get_absolute_url(), "/projects/foo")
