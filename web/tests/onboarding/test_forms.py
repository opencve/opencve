import json

import pytest

from cves.constants import PRODUCT_SEPARATOR
from cves.models import Product, Vendor
from onboarding.forms import MAX_SUBSCRIPTIONS, OnboardingForm
from organizations.models import Organization


@pytest.mark.parametrize(
    "payload,errors",
    [
        ({"organization": "myorga", "project": "myproject"}, {}),
        (
            {},
            {
                "organization": ["This field is required."],
                "project": ["This field is required."],
            },
        ),
        (
            {"organization": "with'quote", "project": "with'quote"},
            {
                "organization": ["Special characters (except dash) are not accepted"],
                "project": ["Special characters (except dash) are not accepted"],
            },
        ),
        (
            {"organization": "add", "project": "add"},
            {
                "organization": ["This organization is reserved."],
                "project": ["This project is reserved."],
            },
        ),
    ],
)
def test_onboarding_form(db, payload, errors):
    form = OnboardingForm(data=payload)
    assert form.errors == errors


def test_onboarding_form_existing_organization(db):
    Organization.objects.create(name="myorga")
    form = OnboardingForm(data={"organization": "myorga", "project": "myproject"})
    assert form.errors == {"organization": ["This organization name is not available."]}


def test_clean_selected_subscriptions_empty_or_missing(db):
    """Empty or missing selected_subscriptions returns [] and form is valid."""
    for payload in [
        {
            "organization": "myorga",
            "project": "myproject",
            "selected_subscriptions": "",
        },
        {
            "organization": "myorga",
            "project": "myproject",
            "selected_subscriptions": "   ",
        },
        {"organization": "myorga", "project": "myproject"},
    ]:
        form = OnboardingForm(data=payload)
        assert form.is_valid(), form.errors
        assert form.cleaned_data["selected_subscriptions"] == []


def test_clean_selected_subscriptions_invalid_json(db):
    """Invalid JSON raises ValidationError."""
    form = OnboardingForm(
        data={
            "organization": "myorga",
            "project": "myproject",
            "selected_subscriptions": "not valid json",
        }
    )
    assert not form.is_valid()
    assert form.errors["selected_subscriptions"] == ["Invalid subscriptions data."]


def test_clean_selected_subscriptions_not_a_list(db):
    """Value that is JSON but not a list raises ValidationError."""
    form = OnboardingForm(
        data={
            "organization": "myorga",
            "project": "myproject",
            "selected_subscriptions": json.dumps({"foo": "bar"}),
        }
    )
    assert not form.is_valid()
    assert form.errors["selected_subscriptions"] == ["Invalid subscriptions data."]


def test_clean_selected_subscriptions_too_many_items(db):
    """More than MAX_SUBSCRIPTIONS items raises ValidationError."""
    max_n = MAX_SUBSCRIPTIONS
    form = OnboardingForm(
        data={
            "organization": "myorga",
            "project": "myproject",
            "selected_subscriptions": json.dumps(
                ["v" + str(i) for i in range(max_n + 1)]
            ),
        }
    )
    assert not form.is_valid()
    assert "You can select at most" in form.errors["selected_subscriptions"][0]
    assert str(max_n) in form.errors["selected_subscriptions"][0]


def test_clean_selected_subscriptions_vendor_does_not_exist(db):
    """Unknown vendor name raises ValidationError."""
    form = OnboardingForm(
        data={
            "organization": "myorga",
            "project": "myproject",
            "selected_subscriptions": json.dumps(["unknown_vendor"]),
        }
    )
    assert not form.is_valid()
    assert form.errors["selected_subscriptions"] == [
        "Vendor does not exist: 'unknown_vendor'"
    ]


def test_clean_selected_subscriptions_product_does_not_exist(db):
    """Unknown product (or vendor) for product key raises ValidationError."""
    vendor = Vendor.objects.create(name="python")
    Product.objects.create(name="django", vendor=vendor)
    # Product "flask" does not exist for vendor "python"
    form = OnboardingForm(
        data={
            "organization": "myorga",
            "project": "myproject",
            "selected_subscriptions": json.dumps([f"python{PRODUCT_SEPARATOR}flask"]),
        }
    )
    assert not form.is_valid()
    assert "Product does not exist" in form.errors["selected_subscriptions"][0]


def test_clean_selected_subscriptions_product_vendor_does_not_exist(db):
    """Product key with non-existent vendor raises ValidationError."""
    form = OnboardingForm(
        data={
            "organization": "myorga",
            "project": "myproject",
            "selected_subscriptions": json.dumps(
                [f"unknown_vendor{PRODUCT_SEPARATOR}product1"]
            ),
        }
    )
    assert not form.is_valid()
    assert "Product does not exist" in form.errors["selected_subscriptions"][0]


def test_clean_selected_subscriptions_empty_product_name(db):
    """Product key with empty product name yields Product does not exist."""
    Vendor.objects.create(name="vendor")
    form = OnboardingForm(
        data={
            "organization": "myorga",
            "project": "myproject",
            "selected_subscriptions": json.dumps([f"vendor{PRODUCT_SEPARATOR}"]),
        }
    )
    assert not form.is_valid()
    assert "Product does not exist" in form.errors["selected_subscriptions"][0]


def test_clean_selected_subscriptions_valid_vendors_only(db):
    """Valid vendor names are accepted and returned."""
    Vendor.objects.create(name="python")
    Vendor.objects.create(name="django")
    form = OnboardingForm(
        data={
            "organization": "myorga",
            "project": "myproject",
            "selected_subscriptions": json.dumps(["python", "django"]),
        }
    )
    assert form.is_valid(), form.errors
    assert form.cleaned_data["selected_subscriptions"] == ["python", "django"]


def test_clean_selected_subscriptions_valid_products_only(db):
    """Valid product keys (vendor$PRODUCT$product) are accepted and returned."""
    vendor = Vendor.objects.create(name="python")
    Product.objects.create(name="django", vendor=vendor)
    form = OnboardingForm(
        data={
            "organization": "myorga",
            "project": "myproject",
            "selected_subscriptions": json.dumps([f"python{PRODUCT_SEPARATOR}django"]),
        }
    )
    assert form.is_valid(), form.errors
    assert form.cleaned_data["selected_subscriptions"] == [
        f"python{PRODUCT_SEPARATOR}django"
    ]


def test_clean_selected_subscriptions_valid_mix(db):
    """Mix of vendors and products is accepted."""
    v1 = Vendor.objects.create(name="python")
    Product.objects.create(name="django", vendor=v1)
    Vendor.objects.create(name="linux")
    form = OnboardingForm(
        data={
            "organization": "myorga",
            "project": "myproject",
            "selected_subscriptions": json.dumps(
                ["python", f"python{PRODUCT_SEPARATOR}django", "linux"]
            ),
        }
    )
    assert form.is_valid(), form.errors
    assert form.cleaned_data["selected_subscriptions"] == [
        "python",
        f"python{PRODUCT_SEPARATOR}django",
        "linux",
    ]


def test_clean_selected_subscriptions_skips_empty_or_non_strings(db):
    """Empty strings and non-string items in the list are skipped."""
    Vendor.objects.create(name="python")
    form = OnboardingForm(
        data={
            "organization": "myorga",
            "project": "myproject",
            "selected_subscriptions": json.dumps(["python", "", "  ", None, 42]),
        }
    )
    assert form.is_valid(), form.errors
    assert form.cleaned_data["selected_subscriptions"] == ["python"]


def test_clean_email_required_when_notifications_enabled(db):
    """When enable_email_notification is True, notification_email is required."""
    form = OnboardingForm(
        data={
            "organization": "myorga",
            "project": "myproject",
            "enable_email_notification": "1",
            "notification_email": "",
        }
    )
    assert not form.is_valid()
    assert "Email is required when enabling notifications" in str(
        form.errors["notification_email"]
    )


def test_clean_email_not_required_when_notifications_disabled(db):
    """When enable_email_notification is False, notification_email can be empty."""
    form = OnboardingForm(
        data={
            "organization": "myorga",
            "project": "myproject",
            "enable_email_notification": "",
            "notification_email": "",
        }
    )
    assert form.is_valid(), form.errors
