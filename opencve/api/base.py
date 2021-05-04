from functools import wraps

from flask import request
from flask import current_app as app
from flask_restful import Resource, HTTPException

from opencve.extensions import limiter
from opencve.models.users import User


def auth_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth = request.authorization

        def error_message():
            return (
                {"message": "Authentication required."},
                401,
                {"WWW-Authenticate": 'Basic realm="Authentication Required"'},
            )

        # Auth not provided
        if not auth:
            return error_message()

        # User not found
        user = User.query.filter_by(username=auth.username).first()
        if not user:
            return error_message()

        # Bad credentials
        if not app.user_manager.verify_password(auth.password, user.password):
            return error_message()

        f = func(*args, **kwargs)

        return f

    return wrapper


class BaseResource(Resource):
    decorators = [
        limiter.shared_limit(
            scope="api",
            limit_value=lambda: app.config["RATELIMIT_VALUE"],
            key_func=lambda: request.authorization.username,
        ),
        auth_required,
    ]
