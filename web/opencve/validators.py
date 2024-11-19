from django.core.validators import RegexValidator


slug_regex_validator = RegexValidator(
    regex=r"^[a-zA-Z0-9\-]+$",
    message="Special characters (except dash) are not accepted",
)
