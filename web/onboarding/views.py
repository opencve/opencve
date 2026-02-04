from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.messages.views import SuccessMessageMixin
from django.db import transaction
from django.http import JsonResponse
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.utils.timezone import now
from django.views import View
from django.views.generic import FormView

from cves.constants import PRODUCT_SEPARATOR
from cves.models import Product, Vendor
from onboarding.forms import OnboardingForm
from organizations.models import Membership, Organization
from projects.models import Notification, Project


class OnboardingMixin:
    """Ensure onboarding views are only available for users without organization."""

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated and getattr(
            request, "current_organization", None
        ):
            return redirect("home")
        return super().dispatch(request, *args, **kwargs)


class SearchVendorsProductsView(OnboardingMixin, LoginRequiredMixin, View):
    """JSON endpoint to search vendors and products by name (for onboarding step 2)."""

    def get(self, request):
        q = (request.GET.get("q") or "").strip().lower()
        if not q:
            return JsonResponse({"vendors": [], "products": []})

        vendors_qs = Vendor.objects.filter(name__contains=q).order_by("name")[:50]
        vendors_list = [
            {"name": v.name, "human_name": v.human_name} for v in vendors_qs
        ]

        products_qs = (
            Product.objects.filter(name__contains=q)
            .select_related("vendor")
            .order_by("vendor__name", "name")[:50]
        )
        products_list = [
            {
                "name": p.name,
                "vendor": p.vendor.name,
                "vendored_name": p.vendored_name,
                "human_name": p.human_name,
            }
            for p in products_qs
        ]

        # Also include products whose vendor name matches (if not already in list)
        seen_vendored = {p["vendored_name"] for p in products_list}
        vendors_names = {v["name"] for v in vendors_list}
        products_by_vendor = (
            Product.objects.filter(vendor__name__contains=q)
            .exclude(vendor__name__in=vendors_names)
            .select_related("vendor")
            .order_by("vendor__name", "name")[:50]
        )
        for p in products_by_vendor:
            if len(products_list) >= 50:
                break
            if p.vendored_name not in seen_vendored:
                seen_vendored.add(p.vendored_name)
                products_list.append(
                    {
                        "name": p.name,
                        "vendor": p.vendor.name,
                        "vendored_name": p.vendored_name,
                        "human_name": p.human_name,
                    }
                )

        return JsonResponse({"vendors": vendors_list, "products": products_list})


class OnboardingFormView(
    OnboardingMixin, LoginRequiredMixin, SuccessMessageMixin, FormView
):
    template_name = "onboarding/index.html"
    form_class = OnboardingForm
    success_url = reverse_lazy("home")
    success_message = (
        "Welcome to OpenCVE! You can now subscribe to "
        "vendors or products to start tracking their CVEs "
        "and stay updated on vulnerabilities."
    )

    def get_initial(self):
        initial = super().get_initial()
        initial["notification_email"] = self.request.user.email
        return initial

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        pending_invitations = Membership.objects.filter(
            user=self.request.user, date_joined__isnull=True
        ).select_related("organization")
        context["pending_invitations"] = pending_invitations
        return context

    @transaction.atomic
    def form_valid(self, form):
        data = form.cleaned_data
        date_now = now()

        organization = Organization.objects.create(name=data["organization"])
        Membership.objects.create(
            user=self.request.user,
            organization=organization,
            role=Membership.OWNER,
            date_invited=date_now,
            date_joined=date_now,
        )

        subscriptions = {"vendors": [], "products": []}
        selected = data.get("selected_subscriptions") or []
        for item in selected:
            if PRODUCT_SEPARATOR in item:
                subscriptions["products"].append(item)
            else:
                subscriptions["vendors"].append(item)

        project = Project.objects.create(
            name=data["project"],
            organization=organization,
            subscriptions=subscriptions,
        )

        if data.get("enable_email_notification"):
            Notification.objects.create(
                name="Email notifications",
                type="email",
                is_enabled=True,
                project=project,
                configuration={
                    "types": ["created", "first_time"],
                    "extras": {"email": data["notification_email"]},
                    "metrics": {"cvss31": str(data["cvss31_min"])},
                },
            )

        return super().form_valid(form)
