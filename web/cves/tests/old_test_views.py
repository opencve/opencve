from django.test import Client, TestCase, override_settings
from django.urls import resolve, reverse
from tests.utils import get_kb_dir

from cves.models import Cve
from users.models import User


@override_settings(LOCAL_REPO_PATH=get_kb_dir())
class CveViewTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        User.objects.create_user(username="john", password="password")
        Cve.objects.create(
            cve_id="CVE-2023-0001", sources={"nvd": "nvd/2023/CVE-2023-0001.json"}
        )

    def test_home_anonymous_redirection(self):
        response = self.client.get("/")
        self.assertRedirects(response, reverse("cves"))

    def test_home_authentificated_redirection(self):
        self.client.login(username="john", password="password")
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            resolve(response.context["request"].path_info).url_name, "home"
        )

    def test_cvelistview(self):
        # self.client.login(username="john", password="password")
        response = self.client.get("/", follow=True)
        self.assertTrue(len(response.context["cves"]) == 1)
