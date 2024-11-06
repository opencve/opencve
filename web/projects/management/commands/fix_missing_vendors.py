from cves.constants import PRODUCT_SEPARATOR
from opencve.commands import BaseCommand
from projects.models import Project
from cves.models import Vendor, Product


class Command(BaseCommand):
    help = """
    This command reimports missing vendors and products that were not
    imported from an OpenCVE v1 instance. See the
    https://docs.opencve.io/troubleshooting/#why-am-i-seeing-404-not-found-on-some-subscriptions
    documentation for more information.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.projects = []
        self.raw_vendors = []
        self.raw_products = []

        self.new_vendors = {}
        self.new_products = set()

    def fetch_records(self):
        """
        Select all the initial records.
        """
        self.projects = Project.objects.all()
        self.raw_vendors = list(Vendor.objects.values_list("name", flat=True))
        self.raw_products = [
            f"{p[1]}{PRODUCT_SEPARATOR}{p[0]}"
            for p in Product.objects.values_list("name", "vendor__name")
        ]
        self.info(
            f"Found {self.blue(len(self.projects))} projects, "
            f"{self.blue(len(self.raw_vendors))} vendors "
            f"and {self.blue(len(self.raw_products))} products"
        )

    def search_missing_vendors(self):
        """
        Compare the user's subscriptions with the existing records,
        then list all the new records to create.
        """
        for project in self.projects:

            for project_vendor in project.subscriptions.get("vendors"):
                if project_vendor not in self.raw_vendors:
                    self.raw_vendors.append(project_vendor)
                    self.new_vendors[project_vendor] = Vendor(name=project_vendor)

            for project_product in project.subscriptions.get("products"):
                if project_product not in self.raw_products:
                    v, _ = Vendor.objects.get_or_create(
                        name=project_product.split(PRODUCT_SEPARATOR)[0]
                    )

                    # This vendor no longer needs to be added later
                    self.raw_vendors.append(v.name)
                    if v.name in self.new_vendors.keys():
                        del self.new_vendors[v.name]

                    self.new_products.add(
                        Product(
                            name=project_product.split(PRODUCT_SEPARATOR)[1],
                            vendor=v,
                        )
                    )
                    self.raw_products.append(project_product)

        self.info(
            f"Found {self.blue(len(self.new_vendors))} vendors "
            f"and {self.blue(len(self.new_products))} products to create"
        )

    def handle(self, *args, **options):
        with self.timed_operation("Fetching records in database"):
            self.fetch_records()

        with self.timed_operation("Searching the missing vendors & products"):
            self.search_missing_vendors()

        with self.timed_operation("Inserting the new objects"):
            Vendor.objects.bulk_create(self.new_vendors.values())
            Product.objects.bulk_create(self.new_products)
