from django.conf import settings
from django.contrib.auth.mixins import AccessMixin


class RequestViewMixin:
    def get_form_kwargs(self):
        """
        Inject the current request (useful to check the authenticated
        user in the clean* functions for instance).
        """
        kwargs = super(RequestViewMixin, self).get_form_kwargs()
        kwargs["request"] = self.request
        return kwargs


class AnonymousAccessMixin(AccessMixin):
    """
    Let anonymous users access the view, unless the `ENABLE_ANONYMOUS_ACCESS`
    setting is disabled: they are then redirected to the login page.
    """

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated and not getattr(
            settings, "ENABLE_ANONYMOUS_ACCESS", True
        ):
            return self.handle_no_permission()
        return super().dispatch(request, *args, **kwargs)
