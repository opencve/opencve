from notifications.plugins import BaseNotification


class EmailNotification(BaseNotification):
    def test_notification(self):
        raise NotImplementedError

    def notify_changes(self):
        raise NotImplementedError

    def send_report(self):
        raise NotImplementedError
