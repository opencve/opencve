import psycopg2
from urllib.parse import urlparse

from allauth.account.models import EmailAddress
from django.conf import settings
from django.utils.timezone import now

from cves.constants import PRODUCT_SEPARATOR
from opencve.commands import BaseCommand
from users.models import User
from organizations.models import Membership, Organization
from projects.models import Notification, Project
from users.management.constants import (
    V1_USERS_SQL,
    V1_VENDORS_SQL,
    V1_PRODUCTS_SQL,
)


class Command(BaseCommand):
    @staticmethod
    def get_cursor():
        uri = urlparse(settings.OPENCVE_V1_DATABASE_URI)
        connection = psycopg2.connect(
            database=uri.path[1:],
            user=uri.username,
            password=uri.password,
            host=uri.hostname,
            port=uri.port,
        )
        return connection.cursor()

    @staticmethod
    def create_user(user_data):
        # Create the user in the V2 db with the old bcrypt password
        # (Django will hash a new one using Argon2 at the next login)
        user, created = User.objects.get_or_create(
            id=user_data[0],
            created_at=user_data[1],
            username=user_data[3],
            password=f"bcrypt${user_data[4]}",
            email=user_data[5],
            first_name=user_data[6],
            last_name=user_data[7],
            is_active=True,
            is_staff=user_data[8],
            is_superuser=user_data[8],
        )

        # We need to specify to AllAuth that the user is verified
        EmailAddress.objects.get_or_create(
            user=user,
            email=user_data[5],
            verified=True,
            primary=True,
        )

        return user, created

    @staticmethod
    def create_orga(user):
        orga = Organization.objects.create(name=f"{user.username}-orga")

        date_now = now()
        Membership.objects.create(
            user=user,
            organization=orga,
            role=Membership.OWNER,
            date_invited=date_now,
            date_joined=date_now,
        )

        return orga

    def create_project(self, organization, vendors, products, notification, email):
        project = Project.objects.create(
            name="OpenCVE v1",
            description="List of subscriptions imported from OpenCVE v1",
            organization=organization,
            subscriptions={
                "vendors": vendors,
                "products": products,
            },
        )

        Notification.objects.create(
            name="Default Notification",
            type="email",
            is_enabled=True,
            project=project,
            configuration=self.get_notification_configuration(
                notification=notification,
                email=email,
            ),
        )

    def get_vendors_products(self, cur, user_id):
        cur.execute(V1_VENDORS_SQL, {"user_id": user_id})
        vendors = cur.fetchall()
        project_vendors = sorted([v[0] for v in vendors])

        cur.execute(V1_PRODUCTS_SQL, {"user_id": user_id})
        products = cur.fetchall()
        project_products = sorted(
            [f"{p[0]}{PRODUCT_SEPARATOR}{p[1]}" for p in products]
        )

        return project_vendors, project_products

    @staticmethod
    def get_notification_configuration(notification, email):
        event_mapping = {
            "summary": "nvd_summary",
            "first_time": "nvd_first_time",
            "new_cve": "nvd_new",
            "cvss": "nvd_cvss",
            "cpes": "nvd_cpes",
            "cwes": "nvd_cwes",
            "references": "nvd_references",
        }

        configuration = {
            "cvss": notification["cvss"],
            "events": [event_mapping[e] for e in notification["event_types"]],
            "extras": {"email": email},
        }
        return configuration

    def handle(self, *args, **options):
        self.info("Starting the migration of OpenCVE v1 users")
        cur = self.get_cursor()

        # Retrieve all the V1 users
        cur.execute(V1_USERS_SQL)
        v1_users = cur.fetchall()

        msg = f"Found {self.blue(len(v1_users))} users to migrate, adding them in database"
        with self.timed_operation(msg):

            for v1_user in v1_users:
                user_id = v1_user[0]

                # Create the user
                user, created = self.create_user(v1_user)
                if not created:
                    continue

                # Fetch all his vendors and products
                vendors, products = self.get_vendors_products(cur, user_id)
                if not (vendors or products):
                    continue

                # Create an organization and set the user as its owner
                organization = self.create_orga(user)

                # Create a project with the user subscriptions
                self.create_project(
                    organization=organization,
                    vendors=vendors,
                    products=products,
                    notification=v1_user[9],
                    email=v1_user[5],
                )

                self.info(f"User {self.blue(v1_user[3])} ({v1_user[5]}) migrated")
