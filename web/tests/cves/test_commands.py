from cves.models import Cve, Vendor, Product, Weakness
from django.core.management import call_command


def test_import_cves_command_kb_path_not_exists(db, settings):
    """Test that the command fails when KB_REPO_PATH doesn't exist."""
    settings.KB_REPO_PATH = "/nonexistent/path"

    # The command should not raise an exception, but should not import any CVEs
    call_command("import_cves")
    assert Cve.objects.count() == 0


def test_import_cves_command_imports_cves(db, settings):
    """Test that the command imports CVEs from KB files."""
    assert Cve.objects.count() == 0

    # Verify CVEs were created
    call_command("import_cves")
    cve_count = Cve.objects.count()
    assert cve_count > 0


def test_import_cves_command_cve_data_correct(db, open_file):
    """Test that imported CVE data matches the source JSON file."""
    call_command("import_cves")

    # Verify the CVE was created with correct data
    cve_id = "CVE-2021-34181"
    cve_data = open_file(f"kb/2021/{cve_id}.json")
    cve = Cve.objects.get(cve_id=cve_id)
    opencve_data = cve_data["opencve"]

    assert cve.cve_id == cve_id
    assert cve.description == opencve_data["description"]["data"]
    assert cve.title == opencve_data["title"]["data"]
    assert cve.vendors == opencve_data["vendors"]["data"]
    assert cve.weaknesses == opencve_data["weaknesses"]["data"]
    assert cve.metrics == opencve_data["metrics"]


def test_import_cves_command_creates_vendors_and_products(db):
    """Test that the command creates vendors and products from CVE data."""
    assert Vendor.objects.count() == 0
    assert Product.objects.count() == 0

    # CVE-2021-34181 has "tomexam" vendor and "tomexam$PRODUCT$tomexam" product
    call_command("import_cves")
    assert Vendor.objects.filter(name="tomexam").exists()
    vendor = Vendor.objects.get(name="tomexam")
    assert Product.objects.filter(vendor=vendor, name="tomexam").exists()


def test_import_cves_command_creates_weaknesses(db):
    """Test that the command creates weaknesses from CVE data."""
    assert Weakness.objects.count() == 0

    # CVE-2021-44228 has multiple weaknesses: CWE-20, CWE-400, CWE-502
    call_command("import_cves")
    assert Weakness.objects.filter(cwe_id="CWE-20").exists()
    assert Weakness.objects.filter(cwe_id="CWE-400").exists()
    assert Weakness.objects.filter(cwe_id="CWE-502").exists()


def test_import_cves_command_handles_multiple_cves(db):
    """Test that the command handles multiple CVEs correctly."""
    call_command("import_cves")

    # Verify several CVEs are imported
    expected_cves = [
        "CVE-2021-34181",
        "CVE-2021-44228",
        "CVE-2022-20698",
        "CVE-2022-22965",
        "CVE-2022-48703",
        # stop here, sufficient to test the command
    ]

    for cve_id in expected_cves:
        assert Cve.objects.filter(
            cve_id=cve_id
        ).exists(), f"CVE {cve_id} should be imported"


def test_import_cves_command_idempotent(db):
    """Test that running the command multiple times doesn't create duplicates."""
    call_command("import_cves")
    first_count = Cve.objects.count()
    first_cve_ids = sorted(list(Cve.objects.values_list("cve_id", flat=True)))

    call_command("import_cves")
    second_count = Cve.objects.count()
    second_cve_ids = sorted(list(Cve.objects.values_list("cve_id", flat=True)))

    # Verify no duplicates were created
    assert first_count == second_count
    assert first_cve_ids == second_cve_ids
