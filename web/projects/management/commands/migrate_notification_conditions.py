from opencve.commands import BaseCommand
from projects.models import Automation, Notification


class Command(BaseCommand):
    help = """
    This command migrates conditions from existing notifications to automations.
    For each notification, it creates a corresponding automation with:
    - Conditions converted from the notification's event types and CVSS score
    - An action to send the original notification
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.notifications = []
        self.automations_created = 0
        self.automations_skipped = 0

    def fetch_notifications(self):
        """
        Fetch all notifications that have conditions (events or CVSS score).
        """
        self.notifications = Notification.objects.all()
        self.info(
            f"Found {self.blue(len(self.notifications))} notifications to process"
        )

    def convert_event_to_condition(self, event_type):
        """
        Convert old notification event types to new automation condition types.
        """
        event_to_condition_map = {
            "created": "cvss_increased",  # New CVE creation
            "description": "description_changed",
            "title": "title_changed",
            "first_time": None,  # This is not a condition, it's a filter
            "weaknesses": None,  # Not directly mappable
            "cpes": None,  # Not directly mappable
            "vendors": "new_vendor",
            "references": "new_reference",
            "metrics": "cvss_increased",  # Metrics change could mean CVSS increased
        }
        return event_to_condition_map.get(event_type)

    def build_conditions_from_notification(self, notification):
        """
        Build conditions list from notification configuration.
        """
        conditions = []
        config = notification.configuration or {}

        # Convert CVSS 3.1 score condition to new unified format
        metrics = config.get("metrics", {})
        cvss31_score = metrics.get("cvss31", 0)
        if cvss31_score and int(cvss31_score) > 0:
            conditions.append(
                {
                    "type": "cvss_gte",
                    "value": {"version": "v3.1", "value": int(cvss31_score)},
                }
            )

        # Convert event types to conditions
        event_types = config.get("types", [])
        for event_type in event_types:
            condition_type = self.convert_event_to_condition(event_type)
            if condition_type:
                # For CVSS increased, use new format with version
                if condition_type == "cvss_increased":
                    conditions.append(
                        {
                            "type": condition_type,
                            "value": {
                                "version": "v3.1"
                            },  # Default to v3.1 for migrated conditions
                        }
                    )
                # For boolean conditions, value is True
                elif condition_type in [
                    "kev_added",
                    "new_vendor",
                    "new_product",
                    "new_reference",
                    "description_changed",
                    "summary_changed",
                    "title_changed",
                ]:
                    conditions.append({"type": condition_type, "value": True})

        return conditions

    def create_automation_from_notification(self, notification):
        """
        Create an automation from a notification's conditions.
        """
        conditions = self.build_conditions_from_notification(notification)

        # Skip if no conditions were created
        if not conditions:
            self.automations_skipped += 1
            self.warning(
                f"Skipping notification '{notification.name}' (no convertible conditions)"
            )
            return

        # Check if automation with same name already exists
        if Automation.objects.filter(
            project=notification.project, name=notification.name
        ).exists():
            self.automations_skipped += 1
            self.warning(
                f"Skipping notification '{notification.name}' (automation with same name already exists)"
            )
            return

        # Build actions: send the original notification
        actions = [{"type": "send_notification", "value": str(notification.id)}]

        # Create the automation
        automation = Automation.objects.create(
            project=notification.project,
            name=notification.name,
            is_enabled=notification.is_enabled,
            configuration={"conditions": conditions, "actions": actions},
        )

        self.automations_created += 1
        self.success(
            f"Created automation '{automation.name}' with {len(conditions)} condition(s) and {len(actions)} action(s)"
        )

    def handle(self, *args, **options):
        with self.timed_operation("Fetching notifications"):
            self.fetch_notifications()

        with self.timed_operation("Creating automations from notifications"):
            for notification in self.notifications:
                self.create_automation_from_notification(notification)

        self.info(
            f"Migration complete: {self.blue(self.automations_created)} automations created, "
            f"{self.blue(self.automations_skipped)} skipped"
        )
