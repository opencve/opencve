import requests
from requests.exceptions import HTTPError, RequestException

from projects.notifications import BaseNotification


class WebhookNotification(BaseNotification):
    def __init__(self, config):
        super().__init__(config)
        self.headers = {h["name"]: h["value"] for h in self.config["headers"]}

    def post(self, payload):
        try:
            response = requests.post(
                self.config["url"],
                headers=self.headers,
                json=payload,
                timeout=2,
            )
            response.raise_for_status()
        except (HTTPError, RequestException) as err:
            return False, str(err)

        return True, response.text

    def test_notification(self):
        return self.post({"type": "test", "message": self.TEST_MESSAGE})

    def notify_changes(self, data):
        return self.post(data)

    def send_report(self, data):
        return self.post(data)
