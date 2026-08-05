def accessible_projects_for_request(request):
    """Context processor: projects visible in the sidebar for the current user."""
    if not request.user.is_authenticated:
        return {"accessible_projects": []}
    org = getattr(request, "current_organization", None)
    if not org:
        return {"accessible_projects": []}
    from authorization.context import get_authorization_context

    ctx = get_authorization_context(request)
    return {"accessible_projects": list(ctx.accessible_projects())}
