"""
Use the `opencve/conf/.env` file to customize the required settings
and the `opencve/conf/settings.py` file to override the other ones.
"""

import environ

from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent.parent

env = environ.Env()
env.prefix = "OPENCVE_"
environ.Env.read_env(BASE_DIR / "opencve/conf/.env")

SECRET_KEY = env.str("SECRET_KEY", default="change_me")
DEBUG = False

ALLOWED_HOSTS = ["*"]


# Application definition
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.humanize",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.postgres",
    "django_extensions",
    "django_prometheus",
    "allauth",
    "allauth.account",
    "allauth.socialaccount",
    "auditlog",
    "crispy_forms",
    "crispy_bootstrap3",
    "debug_toolbar",
    "hijack",
    "hijack.contrib.admin",
    "rest_framework",
    "changes",
    "cves",
    "onboarding",
    "organizations",
    "projects",
    "users",
]

MIDDLEWARE = [
    "django_prometheus.middleware.PrometheusBeforeMiddleware",
    "debug_toolbar.middleware.DebugToolbarMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "allauth.account.middleware.AccountMiddleware",
    "hijack.middleware.HijackUserMiddleware",
    "cves.middlewares.SanitizeInputMiddleware",
    "onboarding.middlewares.OnboardingMiddleware",
    "organizations.middlewares.OrganizationMiddleware",
    "auditlog.middleware.AuditlogMiddleware",
    "django_prometheus.middleware.PrometheusAfterMiddleware",
]

ROOT_URLCONF = "opencve.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "opencve.context_processors.canonical_url_context",
            ],
        },
    },
]

WSGI_APPLICATION = "opencve.wsgi.application"

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "allauth.account.auth_backends.AuthenticationBackend",
]

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "DEBUG",
    },
}

# Database
DATABASES = {
    "default": env.db(
        "DATABASE_URL",
        default="postgresql://username:password@example.com:5432/opencve_web",
    )
}
DATABASES["default"]["ENGINE"] = "django_prometheus.db.backends.postgresql"

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

# Password hashers
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
    "django.contrib.auth.hashers.ScryptPasswordHasher",
    "django.contrib.auth.hashers.BCryptPasswordHasher",
]

# Internationalization
LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = "/app/static/"

# Default primary key field type
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Template used by Django-Crispy
CRISPY_TEMPLATE_PACK = "bootstrap3"

# Redirection page for authentication
LOGIN_REDIRECT_URL = "home"
LOGOUT_REDIRECT_URL = "cves"
LOGIN_URL = "account_login"

# User settings
AUTH_USER_MODEL = "users.User"
ACCOUNT_CHANGE_EMAIL = True
ACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_EMAIL_VERIFICATION = "mandatory"
ACCOUNT_EMAIL_SUBJECT_PREFIX = "[OpenCVE] "
ACCOUNT_LOGOUT_REDIRECT_URL = "account_login"
ACCOUNT_AUTHENTICATION_METHOD = "username_email"
ACCOUNT_FORMS = {
    "login": "users.forms.LoginForm",
    "signup": "users.forms.RegisterForm",
    "reset_password": "users.forms.PasswordResetForm",
    "reset_password_from_key": "users.forms.SetPasswordForm",
}
SOCIALACCOUNT_FORMS = {"signup": "users.forms.CustomSocialSignupForm"}
SOCIALACCOUNT_AUTO_SIGNUP = False
SOCIALACCOUNT_EMAIL_REQUIRED = False
SOCIALACCOUNT_EMAIL_AUTHENTICATION = True
SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT = True

# Audit Logs
AUDITLOG_INCLUDE_TRACKING_MODELS = (
    "organizations.Organization",
    "organizations.Membership",
    "projects.Project",
    "projects.Notification",
    "users.UserTag",
    "users.CveTag",
    {"model": "users.User", "mask_fields": ["password"]},
)

# Email backend
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

# Internal IPs
INTERNAL_IPS = ["127.0.0.1"]
REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 10,
}

# Number of days to keep the activation link active
ACCOUNT_EMAIL_CONFIRMATION_EXPIRE_DAYS = 7

# The default protocol used for when generating accounts URLs
ACCOUNT_DEFAULT_HTTP_PROTOCOL = "http"

# Number of vendors and products to display the CVE listing
COUNT_EXCERPT = 3

# The local folder where the repository `opencve-kb` is cloned
KB_REPO_PATH = env.str("KB_REPO_PATH", default="/path/to/kb")

# The local folder where the repository `cvelistV5` is cloned
MITRE_REPO_PATH = env.str("MITRE_REPO_PATH", default="/path/to/mitre")

# The local folder where the repository `opencve-nvd` is cloned
NVD_REPO_PATH = env.str("NVD_REPO_PATH", default="/path/to/nvd")

# The local folder where the repository `opencve-redhat` is cloned
REDHAT_REPO_PATH = env.str("REDHAT_REPO_PATH", default="/path/to/redhat")

# The local folder where the repository `vulnrichment` is cloned
VULNRICHMENT_REPO_PATH = env.str(
    "VULNRICHMENT_REPO_PATH", default="/path/to/vulnrichment"
)

# OpenCVE v1 database URI, used to migrate data from v1 to v2
V1_DATABASE = env.db(
    "V1_DATABASE",
    default="postgresql://username:password@example.com:5432/opencve_v1",
)

# Redirect user to onboarding view if they do not belong to an organization
ENABLE_ONBOARDING = True

# Maximum number of fields to allow in a CVE Advanced Search query
CVES_ADVANCED_SEARCH_MAX_FIELDS = 5
