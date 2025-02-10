from django.contrib import messages
from django.http import Http404


VIEW_WITHOUT_REDIRECTION = [
    "OrganizationInvitationView",
]


class OrganizationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    @staticmethod
    def get_view_name(view_func):
        if hasattr(view_func, "view_class"):
            return view_func.view_class.__name__

        return view_func.__name__

    def process_view(self, request, view_func, view_args, view_kwargs):
        request.current_organization = None
        request.user_organizations = []

        if not request.user.is_authenticated:
            return

        # Retrieve the user organizations
        organizations = request.user.list_organizations()
        if not organizations:
            return

        # Check if the url contains an organization
        org_name_in_url = view_kwargs.get("org_name")
        view_name = self.get_view_name(view_func)

        organization = None
        if org_name_in_url and view_name not in VIEW_WITHOUT_REDIRECTION:
            organization = next(
                (org for org in organizations if org.name == org_name_in_url), None
            )

            # User is attempting to access an organization he's not a member of
            if not organization:
                raise Http404

            # Update the session if the organization changes
            if str(organization.id) != request.session.get("current_organization_id"):
                request.session["current_organization_id"] = str(organization.id)
                messages.info(
                    request,
                    f"You are now connected to the organization {organization.name}.",
                )

        # If no organization in the url, use the session one
        else:
            organization_id = request.session.get("current_organization_id")
            if organization_id:
                organization = next(
                    (org for org in organizations if str(org.id) == organization_id),
                    None,
                )

        # By default, use the first organization
        if not organization:
            organization = organizations[0]
            request.session["current_organization_id"] = str(organization.id)

        # Update the request context
        request.current_organization = organization
        request.user_organizations = organizations
