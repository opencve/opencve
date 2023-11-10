from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import (
    LoginView,
    PasswordChangeView,
    PasswordResetConfirmView,
    PasswordResetView,
)
from django.contrib.messages.views import SuccessMessageMixin
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse_lazy
from django.views.generic import (
    CreateView,
    DeleteView,
    ListView,
    UpdateView,
)

from cves.models import Product, Vendor
from users.forms import (
    LoginForm,
    PasswordChangeForm,
    PasswordResetForm,
    ProfileChangeForm,
    RegisterForm,
    SetPasswordForm,
    UserTagForm,
)
from users.models import CveTag, UserTag
from opencve.utils import is_valid_uuid


def account(request):
    return redirect("projects")


class RequestViewMixin:
    def get_form_kwargs(self):
        """
        Inject the current request (useful to check the authenticated
        user in the clean* functions for instance).
        """
        kwargs = super(RequestViewMixin, self).get_form_kwargs()
        kwargs["request"] = self.request
        return kwargs


# TAGS views


class TagsListView(LoginRequiredMixin, ListView):
    context_object_name = "tags"
    template_name = "users/account/tags.html"

    def get_queryset(self):
        query = UserTag.objects.filter(user=self.request.user).all()
        return query.order_by("name")


class TagCreateView(
    LoginRequiredMixin, SuccessMessageMixin, RequestViewMixin, CreateView
):
    form_class = UserTagForm
    template_name = "users/account/tag_create_update.html"
    success_url = reverse_lazy("tags")
    success_message = "The tag has been successfully created."

    def form_valid(self, form):
        form.instance.user = self.request.user
        return super().form_valid(form)


class TagEditView(
    LoginRequiredMixin, SuccessMessageMixin, RequestViewMixin, UpdateView
):
    model = UserTag
    form_class = UserTagForm
    template_name = "users/account/tag_create_update.html"
    success_url = reverse_lazy("tags")
    success_message = "The tag has been successfully updated."
    slug_field = "name"
    slug_url_kwarg = "name"

    def get_object(self, queryset=None):
        return get_object_or_404(
            UserTag, user=self.request.user, name=self.kwargs["name"]
        )

    def get_form(self, form_class=None):
        form = super(TagEditView, self).get_form()
        form.fields["name"].disabled = True
        return form


class TagDeleteView(LoginRequiredMixin, SuccessMessageMixin, DeleteView):
    model = UserTag
    slug_field = "name"
    slug_url_kwarg = "name"
    template_name = "users/account/delete_tag.html"
    success_message = "The tag has been deleted."
    success_url = reverse_lazy("tags")

    def get(self, request, *args, **kwargs):
        count = CveTag.objects.filter(
            user=self.request.user, tags__contains=kwargs["name"]
        ).count()
        if count:
            messages.error(
                self.request,
                f"The tag {kwargs['name']} is still associated to {count} CVE(s), detach them before removing the tag.",
            )
            return redirect("tags")

        return super().get(request, *args, **kwargs)

    def get_object(self, queryset=None):
        return get_object_or_404(
            UserTag, user=self.request.user, name=self.kwargs["name"]
        )


# PROFILE views


class SettingsProfileView(LoginRequiredMixin, SuccessMessageMixin, UpdateView):
    form_class = ProfileChangeForm
    template_name = "users/account/settings_profile.html"
    success_url = reverse_lazy("settings_profile")
    success_message = "Your profile has been updated."

    def get_object(self, queryset=None):
        return self.request.user


class SettingsPasswordView(LoginRequiredMixin, SuccessMessageMixin, PasswordChangeView):
    form_class = PasswordChangeForm
    template_name = "users/account/settings_password.html"
    success_url = reverse_lazy("settings_password")
    success_message = "Your password has been updated."


class CustomLoginView(LoginView):
    form_class = LoginForm
    template_name = "users/login.html"
    redirect_authenticated_user = True


class CustomPasswordResetView(PasswordResetView):
    form_class = PasswordResetForm
    template_name = "users/password_reset.html"
    success_url = reverse_lazy("login")

    def form_valid(self, form):
        resp = super().form_valid(form)
        messages.success(
            self.request,
            f"We've emailed you instructions for setting your password, if an account exists with the email you entered.",
        )
        return resp


class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    form_class = SetPasswordForm
    template_name = "users/password_reset_confirm.html"
    success_url = reverse_lazy("login")

    def form_valid(self, form):
        resp = super().form_valid(form)
        messages.success(
            self.request,
            f"Your password has been set. You may go ahead and log in now.",
        )
        return resp


def register(request):
    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            messages.success(
                request, f"Registration successful, email sent to {user.email}"
            )
            return redirect("login")
    else:
        form = RegisterForm()
    return render(
        request=request, template_name="users/register.html", context={"form": form}
    )


def subscribe(request):
    response = {}

    # Only authenticated users can subscribe
    if not request.method == "POST" or not request.user.is_authenticated:
        raise Http404()

    # Handle the parameters
    action = request.POST.get("action")
    obj = request.POST.get("obj")
    obj_id = request.POST.get("id")

    if (
        not all([action, obj, obj_id])
        or not is_valid_uuid(obj_id)
        or action not in ["subscribe", "unsubscribe"]
        or obj not in ["vendor", "product"]
    ):
        raise Http404()

    # Vendor subscription
    if obj == "vendor":
        vendor = get_object_or_404(Vendor, id=obj_id)
        if action == "subscribe":
            request.user.vendors.add(vendor)
            response = {"status": "ok", "message": "vendor added"}
        else:
            request.user.vendors.remove(vendor)
            response = {"status": "ok", "message": "vendor removed"}

    # Product subscription
    if obj == "product":
        product = get_object_or_404(Product, id=obj_id)
        if action == "subscribe":
            request.user.products.add(product)
            response = {"status": "ok", "message": "product added"}
        else:
            request.user.products.remove(product)
            response = {"status": "ok", "message": "product removed"}

    return JsonResponse(response)
