from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.messages.views import SuccessMessageMixin
from django.db import transaction
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.utils.timezone import now
from django.views.generic import FormView

from cves.constants import PRODUCT_SEPARATOR
from cves.models import Cve
from onboarding.forms import OnboardingForm
from organizations.models import Membership, Organization
from projects.models import Notification, Project
from users.models import UserTag, CveTag


class OnboardingFormView(LoginRequiredMixin, SuccessMessageMixin, FormView):
    template_name = "onboarding/index.html"
    form_class = OnboardingForm
    success_url = reverse_lazy("home")
    success_message = (
        "Welcome to OpenCVE! You can now subscribe to "
        "vendors or products to start tracking their CVEs "
        "and stay updated on vulnerabilities."
    )

    def dispatch(self, request, *args, **kwargs):
        """
        The onboarding process is only available for user without organization.
        """
        if request.user.is_authenticated and request.user_organization:
            return redirect("home")
        return super().dispatch(request, *args, **kwargs)

    @transaction.atomic
    def form_valid(self, form):
        """
        Create the organization and the project with some example data.
        """
        data = form.cleaned_data
        date_now = now()

        # Create the organization and grant the user as owner
        organization = Organization.objects.create(name=data["organization"])
        Membership.objects.create(
            user=self.request.user,
            organization=organization,
            role=Membership.OWNER,
            date_invited=date_now,
            date_joined=date_now,
        )

        # Create the project with a default notification
        project = Project.objects.create(
            name=data["project"],
            organization=organization,
            subscriptions={
                "vendors": ["linux", "microsoft"],
                "products": [f"djangoproject{PRODUCT_SEPARATOR}django"],
            },
        )

        Notification.objects.create(
            name="Critical Vulnerabilities",
            type="email",
            is_enabled=True,
            project=project,
            configuration={
                "types": [
                    "created",
                    "first_time",
                    "weaknesses",
                    "cpes",
                    "vendors",
                    "metrics",
                ],
                "extras": {"email": self.request.user.email},
                "metrics": {"cvss31": "9"},
            },
        )

        # Create an example tag and associate it to a CVE
        tag, created = UserTag.objects.get_or_create(
            name="log4j", user=self.request.user
        )
        if created:
            tag.description = "This is an example tag"
            tag.color = "#0A0031"
            tag.save()

        # Associate a new tag to a CVE (or add it to the existing tags)
        cve = Cve.objects.filter(cve_id="CVE-2021-44228").first()
        if cve:
            cve_tag = CveTag.objects.filter(user=self.request.user, cve=cve).first()

            if not cve_tag:
                CveTag.objects.create(user=self.request.user, cve=cve, tags=[tag.name])
            elif tag.name not in cve_tag.tags:
                cve_tag.tags.append(tag.name)
                cve_tag.save()

        return super().form_valid(form)
