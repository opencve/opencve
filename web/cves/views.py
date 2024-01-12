import itertools
import json
import operator

from django.core.paginator import Paginator
from django.db.models import F, Q
from django.http import Http404, JsonResponse
from django.shortcuts import get_object_or_404, redirect
from django.views.generic import DetailView, ListView, TemplateView
from django.contrib.auth.mixins import LoginRequiredMixin

from cves.constants import PRODUCT_SEPARATOR
from cves.models import Cve, Product, Vendor, Weakness
from cves.utils import convert_cpes, list_weaknesses
from opencve.utils import is_valid_uuid
from projects.models import Project
from changes.models import Change
from users.models import CveTag, UserTag
from organizations.mixins import OrganizationRequiredMixin


def list_filtered_cves(request):
    """
    This function takes a query in parameter and filter the list
    of returned CVEs based on given filters (search, vendors, cvss...)
    """
    query = Cve.objects.order_by("-updated_at")

    search = request.GET.get("search")
    if search:
        query = query.filter(
            Q(cve_id__icontains=search)
            | Q(description__icontains=search)
            | Q(vendors__contains=search)
        )

    # Filter by weakness
    weakness = request.GET.get("weakness")
    if weakness:
        query = query.filter(weaknesses__contains=weakness)

    # Filter by CVSS score
    cvss = request.GET.get("cvss", "").lower()
    if cvss in [
        "empty",
        "low",
        "medium",
        "high",
        "critical",
    ]:
        if cvss == "empty":
            query = query.filter(metrics__v31__isnull=True)
        if cvss == "low":
            query = query.filter(Q(metrics__v31__score__gte=0) & Q(metrics__v31__score__lte=3.9))
        if cvss == "medium":
            query = query.filter(Q(metrics__v31__score__gte=4.0) & Q(metrics__v31__score__lte=6.9))
        if cvss == "high":
            query = query.filter(Q(metrics__v31__score__gte=7.0) & Q(metrics__v31__score__lte=8.9))
        if cvss == "critical":
            query = query.filter(Q(metrics__v31__score__gte=9.0) & Q(metrics__v31__score__lte=10.0))

    # Filter by Vendor and Product
    vendor_param = request.GET.get("vendor", "").replace(" ", "").lower()
    product_param = request.GET.get("product", "").replace(" ", "_").lower()

    if vendor_param:
        vendor = get_object_or_404(Vendor, name=vendor_param)
        query = query.filter(vendors__contains=vendor.name)

        if product_param:
            product = get_object_or_404(Product, name=product_param, vendor=vendor)
            query = query.filter(
                vendors__contains=f"{vendor.name}{PRODUCT_SEPARATOR}{product.name}"
            )

    # Filter by tag
    tag = request.GET.get("tag", "").lower()
    if tag and request.user.is_authenticated:
        tag = get_object_or_404(UserTag, name=tag, user=request.user)
        query = query.filter(cve_tags__tags__contains=tag.name)

    return query.all()


class WeaknessListView(ListView):
    context_object_name = "weaknesses"
    template_name = "cves/weakness_list.html"
    paginate_by = 20

    def get_queryset(self):
        query = Weakness.objects
        if self.request.GET.get("search"):
            query = query.filter(name__icontains=self.request.GET.get("search"))
        return query.order_by("-name")


class VendorListView(ListView):
    context_object_name = "vendors"
    template_name = "cves/vendor_list.html"
    paginate_by = 20

    def get_queryset(self):
        vendors = Vendor.objects.order_by("name").prefetch_related("products")
        if self.request.GET.get("search"):
            vendors = vendors.filter(name__contains=self.request.GET.get("search"))
        return vendors

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Get all products or filter them by vendor
        vendor = self.request.GET.get("vendor")
        products = Product.objects.order_by("name").select_related("vendor")

        # Filter by vendor
        if vendor:
            products = products.filter(vendor__name=vendor)

        # Filter by keyword
        if self.request.GET.get("search"):
            products = products.filter(name__contains=self.request.GET.get("search"))

        # Add the pagination
        paginator = Paginator(products, 20)
        page_number = self.request.GET.get("product_page")
        context["products"] = paginator.get_page(page_number)
        context["paginator_products"] = paginator

        return context


class CveListView(ListView):
    context_object_name = "cves"
    template_name = "cves/cve_list.html"
    paginate_by = 20

    def get_queryset(self):
        return list_filtered_cves(self.request)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        vendor = self.request.GET.get("vendor")
        product = self.request.GET.get("product")
        if vendor:
            context["vendor"] = Vendor.objects.get(name=vendor)

            if product:
                context["product"] = Product.objects.get(
                    name=product, vendor=context["vendor"]
                )

        # List the user tags
        if self.request.user.is_authenticated:
            context["user_tags"] = [
                t.name for t in UserTag.objects.filter(user=self.request.user).all()
            ]

        return context


class CveDetailView(DetailView):
    model = Cve
    slug_field = "cve_id"
    slug_url_kwarg = "cve_id"
    template_name = "cves/cve_detail.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Raw json files
        context["nvd_json"] = json.dumps(context["cve"].nvd_json)
        context["mitre_json"] = json.dumps(context["cve"].mitre_json)

        context["changes"] = Change.objects.filter(cve_id=context["cve"].id).order_by("-created_at")

        """events = Event.objects.filter(cve_id=context["cve"].id).order_by("-created_at")
        context["events_by_time"] = [
            (time, list(evs))
            for time, evs in (
                itertools.groupby(events, operator.attrgetter("created_at"))
            )
        ]"""
        context["events_by_time"] = []

        # Add the associated vendors and weaknesses
        context["vendors"] = convert_cpes(context["cve"].nvd_json.get("configurations", {}))
        context["weaknesses"] = list_weaknesses(context["cve"].weaknesses)

        # Get the CVE tags for the authenticated user
        user_tags = {}
        tags = []

        user = self.request.user
        if user.is_authenticated:
            user_tags = {
                t.name: {"name": t.name, "color": t.color, "description": t.description}
                for t in UserTag.objects.filter(user=self.request.user).all()
            }
            cve_tags = CveTag.objects.filter(
                user=self.request.user, cve=context["cve"]
            ).first()
            if cve_tags:
                tags = [user_tags[cve_tag] for cve_tag in cve_tags.tags]

                # We have to pass an encoded list of tags for the modal box
                context["cve_tags_encoded"] = json.dumps(cve_tags.tags)

        context["user_tags"] = user_tags.keys()
        context["tags"] = tags
        return context

    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            raise Http404()

        cve = self.get_object()
        new_tags = request.POST.getlist("tags", [])

        # Check if all tags are declared by the user
        user_tags = [t.name for t in UserTag.objects.filter(user=request.user).all()]
        for new_tag in new_tags:
            if new_tag not in user_tags:
                raise Http404()

        # Update the CVE tags
        cve_tag = CveTag.objects.filter(user=request.user, cve_id=cve.id).first()
        if not cve_tag:
            cve_tag = CveTag(user=request.user, cve_id=cve.id)
        cve_tag.tags = new_tags
        cve_tag.save()

        return redirect("cve", cve_id=cve.cve_id)


class SubscriptionView(LoginRequiredMixin, OrganizationRequiredMixin, TemplateView):
    template_name = "cves/vendor_subscribe.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        vendor_name = self.request.GET.get("vendor")
        product_name = self.request.GET.get("product")

        # The vendor at least is mandatory
        if not vendor_name:
            raise Http404()

        # Get the vendor data
        vendor = get_object_or_404(Vendor, name=vendor_name)
        obj = vendor
        obj_type = "vendor"
        obj_name = obj.name

        # Get the product data
        if product_name:
            product = get_object_or_404(Product, name=product_name, vendor=vendor)
            obj = product
            obj_type = "product"
            obj_name = f"{vendor.name}{PRODUCT_SEPARATOR}{product.name}"

        # Update the context
        context.update(**{
            "object": obj,
            "object_type": obj_type,
            "object_name": obj_name,
            "projects": Project.objects.filter(organization=self.request.user_organization).order_by("name").all()
        })

        return context

    def post(self, request, *args, **kwargs):
        action = request.POST.get("action")
        obj_type = request.POST.get("obj_type")
        obj_id = request.POST.get("obj_id")
        project_id = request.POST.get("project_id")

        if (
            not all([action, obj_type, obj_id, project_id])
            or not is_valid_uuid(obj_id)
            or not is_valid_uuid(project_id)
            or action not in ["subscribe", "unsubscribe"]
            or obj_type not in ["vendor", "product"]
        ):
            raise Http404()

        # Check if the project belongs to the current organization
        project = get_object_or_404(Project, id=project_id, organization=request.user_organization)

        # Vendor subscription
        if obj_type == "vendor":
            vendor = get_object_or_404(Vendor, id=obj_id)
            project_vendors = set(project.subscriptions.get("vendors"))

            if action == "subscribe":
                project_vendors.add(vendor.name)
            else:
                try:
                    project_vendors.remove(vendor.name)
                except KeyError:
                    raise Http404()

            project.subscriptions["vendors"] = list(project_vendors)
            project.save()

        if obj_type == "product":
            product = get_object_or_404(Product, id=obj_id)
            project_products = set(project.subscriptions.get("products"))

            if action == "subscribe":
                project_products.add(product.vendored_name)
            else:
                try:
                    project_products.remove(product.vendored_name)
                except KeyError:
                    raise Http404()

            project.subscriptions["products"] = list(project_products)
            project.save()

        return JsonResponse({"status": "ok"})
