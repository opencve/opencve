import os
import tempfile
from pathlib import Path
import warnings

from flask_admin import Admin
from flask_admin.base import MenuLink
from werkzeug.middleware.proxy_fix import ProxyFix

from opencve.admin import (
    CveModelView,
    EventModelView,
    HomeView,
    UserModelView,
    VendorModelView,
    ProductModelView,
)
from opencve.configuration import config
from opencve.extensions import CustomEmailManager
from opencve.extensions import (
    cel,
    csrf,
    db,
    debug_toolbar,
    gravatar,
    limiter,
    migrate,
    user_manager,
)
from opencve.models.cve import Cve
from opencve.models.events import Event
from opencve.models.products import Product
from opencve.models.users import User
from opencve.models.vendors import Vendor
from opencve.tasks import CELERYBEAT_SCHEDULE


class Config(object):
    SECRET_KEY = config.get("core", "secret_key")
    USE_REVERSE_PROXY = config.getboolean("core", "use_reverse_proxy", fallback=False)

    DISPLAY_WELCOME = config.getboolean("core", "display_welcome", fallback=False)
    DISPLAY_TERMS = config.getboolean("core", "display_terms", fallback=False)

    # Customize the server name
    if config.get("core", "server_name"):
        SERVER_NAME = config.get("core", "server_name")

    # Database
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = config.get("core", "database_uri")

    # Celery
    CELERY_CONF = {
        "BROKER_URL": config.get(
            "core", "celery_broker_url", fallback="redis://127.0.0.1:6379/0"
        ),
        "CELERY_RESULT_BACKEND": config.get(
            "core", "celery_result_backend", fallback="redis://127.0.0.1:6379/1"
        ),
        "CELERYBEAT_SCHEDULE": CELERYBEAT_SCHEDULE,
        "CELERY_TASK_SERIALIZER": "json",
        "CELERY_RESULT_SERIALIZER": "json",
        "CELERY_ACCEPT_CONTENT": ["json"],
        "CELERYD_HIJACK_ROOT_LOGGER": False,
    }

    # Pagination
    CVES_PER_PAGE = config.getint("core", "cves_per_page", fallback=20)
    VENDORS_PER_PAGE = config.getint("core", "vendors_per_page", fallback=20)
    PRODUCTS_PER_PAGE = config.getint("core", "products_per_page", fallback=20)
    CWES_PER_PAGE = config.getint("core", "cwes_per_page", fallback=20)
    REPORTS_PER_PAGE = config.getint("core", "reports_per_page", fallback=20)
    ALERTS_PER_PAGE = config.getint("core", "alerts_per_page", fallback=20)
    TAGS_PER_PAGE = config.getint("core", "tags_per_page", fallback=20)
    ACTIVITIES_PER_PAGE = config.getint("core", "activities_per_page", fallback=20)

    # ReCaptcha
    DISPLAY_RECAPTCHA = config.getboolean("core", "display_recaptcha", fallback=False)
    RECAPTCHA_PUBLIC_KEY = config.get("core", "recaptcha_site_key")
    RECAPTCHA_PRIVATE_KEY = config.get("core", "recaptcha_secret_key")

    # Vendors and Products excerpt
    COUNT_EXCERPT = 3
    REPORT_COUNT_EXCERPT = 3

    # Flask-User
    USER_APP_NAME = "OpenCVE.io"
    USER_ENABLE_CHANGE_USERNAME = False
    USER_ENABLE_MULTIPLE_EMAILS = True
    USER_AUTO_LOGIN_AFTER_CONFIRM = False

    # Flask-User redirect pages
    USER_AFTER_CHANGE_PASSWORD_ENDPOINT = "user.login"
    USER_AFTER_REGISTER_ENDPOINT = "user.login"
    USER_AFTER_CONFIRM_ENDPOINT = "user.login"
    USER_AFTER_FORGOT_PASSWORD_ENDPOINT = "user.login"
    USER_AFTER_RESET_PASSWORD_ENDPOINT = "user.login"
    USER_AFTER_LOGOUT_ENDPOINT = "user.login"
    USER_AFTER_RESEND_EMAIL_CONFIRMATION_ENDPOINT = "user.login"
    USER_AFTER_EDIT_USER_PROFILE_ENDPOINT = "user.edit_user_profile"

    # Flask-User urls
    USER_LOGIN_URL = "/login"
    USER_LOGOUT_URL = "/logout"
    USER_REGISTER_URL = "/register"
    USER_CHANGE_PASSWORD_URL = "/account/password"
    USER_EDIT_USER_PROFILE_URL = "/account/profile"
    USER_FORGOT_PASSWORD_URL = "/account/forgot-password"
    USER_RESEND_EMAIL_CONFIRMATION_URL = "/account/resend-email-confirmation"

    # API rate limit
    RATELIMIT_ENABLED = config.getboolean("api", "ratelimit_enabled", fallback=False)
    RATELIMIT_VALUE = config.get("api", "ratelimit_value", fallback="3600/hour")
    RATELIMIT_STORAGE_URL = config.get(
        "api", "ratelimit_storage_url", fallback="redis://127.0.0.1:6379/2"
    )
    RATELIMIT_HEADERS_ENABLED = True

    # Mail
    EMAIL_ADAPTER = config.get("mail", "email_adapter", fallback="smtp")
    USER_EMAIL_SENDER_EMAIL = config.get(
        "mail", "email_from", fallback="no-reply@opencve.io"
    )
    MAIL_SERVER = config.get("mail", "smtp_server")
    MAIL_PORT = config.getint("mail", "smtp_port", fallback=465)
    MAIL_USE_TLS = config.getboolean("mail", "smtp_use_tls", fallback=True)
    MAIL_USERNAME = config.get("mail", "smtp_username")

    # ensure compatibility before deprecating "stmp_password"
    # see https://github.com/opencve/opencve/issues/76
    try:
        MAIL_PASSWORD = config.get("mail", "smtp_password")
    except:
        MAIL_PASSWORD = config.get("mail", "stmp_password")

    DEFAULT_MAIL_SENDER = config.get(
        "mail", "email_from", fallback="no-reply@opencve.io"
    )

    @staticmethod
    def init_app(app):
        # Flask-DebugToolbar
        debug_toolbar.init_app(app)

        # Celery
        cel.init_app(app)

        # CSRF protection
        csrf.init_app(app)

        # SQLAlchemy
        db.init_app(app)

        # User
        user_manager.init_app(app, db, User)
        user_manager.email_manager = CustomEmailManager(app)

        # Flask-Gravatar
        gravatar.init_app(app)

        # Flask-Migrate
        migrate.init_app(
            app=app,
            db=db,
            directory=str(Path(__file__).resolve().parent / "migrations"),
        )

        # Reverse proxy should used HTTPS
        if app.config["USE_REVERSE_PROXY"]:
            app.config["PREFERRED_URL_SCHEME"] = "https"
            app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

        # API Ratelimit
        limiter.init_app(app)

        # Flask-Admin
        admin = Admin(
            name="OpenCVE Admin", template_mode="bootstrap3", index_view=HomeView()
        )
        admin.init_app(app)
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", "Fields missing from ruleset")
            admin.add_view(UserModelView(User, db.session))
        admin.add_view(CveModelView(Cve, db.session))
        admin.add_view(EventModelView(Event, db.session))
        admin.add_view(VendorModelView(Vendor, db.session))
        admin.add_view(ProductModelView(Product, db.session))
        admin.add_link(MenuLink(name="Tasks", url="/admin/tasks"))


class ProdConfig(Config):
    ENV = "prod"
    DEBUG = False


class DevConfig(Config):
    ENV = "development"
    DEBUG = True
    DEBUG_TB_INTERCEPT_REDIRECTS = False

    @staticmethod
    def init_app(app):
        Config.init_app(app)


class TestConfig(Config):
    db_file = tempfile.NamedTemporaryFile()

    ENV = "test"
    WTF_CSRF_ENABLED = False
    DEBUG_TB_INTERCEPT_REDIRECTS = False

    @staticmethod
    def init_app(app):
        Config.init_app(app)


env_config = {"development": DevConfig, "test": TestConfig, "production": ProdConfig}
