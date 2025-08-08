def feed_tokens(request):
    """
    Add feed tokens to the template context for authenticated users.
    """
    if request.user.is_authenticated:
        return {
            'feed_tokens': request.user.feed_tokens.all()
        }
    return {'feed_tokens': []}