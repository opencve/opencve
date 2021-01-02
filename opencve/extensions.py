from celery import Celery
from flask_admin import Admin
from flask_debugtoolbar import DebugToolbarExtension
from flask_gravatar import Gravatar
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_user import UserManager, EmailManager
from flask_user.forms import EditUserProfileForm, RegisterForm
from flask_wtf import RecaptchaField
from flask_wtf.csrf import CSRFProtect
from wtforms import validators, StringField

from opencve.admin import HomeView


class CustomUserManager(UserManager):
    """
    Add custom properties in default Flask-User objects.
    """

    def customize(self, app):
        # Add the email field
        class CustomUserProfileForm(EditUserProfileForm):
            email = StringField(
                "Email", validators=[validators.DataRequired(), validators.Email()]
            )

        self.EditUserProfileFormClass = CustomUserProfileForm

        # Add the reCaptcha
        if app.config.get("DISPLAY_RECAPTCHA"):

            class CustomRegisterForm(RegisterForm):
                recaptcha = RecaptchaField()

            self.RegisterFormClass = CustomRegisterForm

        # Allow emails to be send using sendmail
        if app.config.get("EMAIL_ADAPTER") == "sendmail":
            from flask_user.email_adapters import SendmailEmailAdapter

            self.email_adapter = SendmailEmailAdapter(app)


class CustomEmailManager(EmailManager):
    def send_user_report(self, user, **kwargs):
        """Send the 'user report' email."""
        self._render_and_send_email(
            user.email,
            user,
            "emails/report",
            **kwargs,
        )


class FlaskCelery(Celery):
    """
    Provide the init_app function.
    """

    def __init__(self, *args, **kwargs):
        super(FlaskCelery, self).__init__(*args, **kwargs)

        if "app" in kwargs:
            self.init_app(kwargs["app"])

    def init_app(self, app):
        self.app = app
        self.conf.update(app.config.get("CELERY_CONF", {}))


# Flask admin
admin = Admin(name="OpenCVE Admin", template_mode="bootstrap3", index_view=HomeView())

# Debug toolbar
debug_toolbar = DebugToolbarExtension()

# CSRF protection
csrf = CSRFProtect()

# SQLAlchemy
db = SQLAlchemy(session_options={"autoflush": False})

# Flask gravatar
gravatar = Gravatar(
    size=100,
    rating="g",
    default="retro",
    force_default=False,
    use_ssl=True,
    base_url=None,
)

# Flask migrate
migrate = Migrate()

# Flask-User
user_manager = CustomUserManager(None, None, None)

# Celery
cel = FlaskCelery("opencve", include=["opencve.tasks"])
