import pytest

from onboarding.forms import OnboardingForm
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
