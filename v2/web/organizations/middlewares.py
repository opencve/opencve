from organizations.models import Organization


class OrganizationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not request.user.is_authenticated:
            return self.get_response(request)

        # List all organizations associated to the user
        organizations = Organization.objects.filter(
            members=request.user
        ).order_by("name").all()
        if not organizations:
            request.user_organization = None
            request.user_organizations = []
            return self.get_response(request)

        # Select the saved organization if exists
        organization = None
        organization_id = request.session.get("user_organization_id", None)
        if organization_id:
            filtered_organizations = [o for o in organizations if str(o.id) == organization_id]
            if filtered_organizations:
                organization = filtered_organizations[0]

        if not organization:
            organization = organizations[0]
            request.session["user_organization_id"] = str(organization.id)

        request.user_organization = organization
        request.user_organizations = organizations

        return self.get_response(request)
