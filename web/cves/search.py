from django.conf import settings
from django.db.models import Q
import pyparsing as pp

from cves.constants import PRODUCT_SEPARATOR
from cves.models import Cve
from users.models import UserTag
from projects.models import Project


class MaxFieldsExceededException(Exception):
    pass


class BadQueryException(Exception):
    pass


OPERATOR_MAP = {
    "gt": ">",
    "gte": ">=",
    "lt": "<",
    "lte": "<=",
    "exact": "=",
    "icontains": ":",
}
OPERATOR_MAP_BY_SYMBOL = {v: k for k, v in OPERATOR_MAP.items()}


class Filter:
    supported_operators = list(OPERATOR_MAP_BY_SYMBOL.keys())

    def __init__(self, field, operator, value, user=None, request=None):
        self.field = field
        self.operator = operator
        self.value = value
        self.user = user
        self.request = request

    def run(self):
        raise NotImplementedError

    def allowed_operator_str(self):
        if len(self.supported_operators) == 1:
            return f"'{self.supported_operators[0]}'"

        return (
            ", ".join(self.supported_operators[:-1])
            + " or "
            + self.supported_operators[-1]
        )

    def execute(self):
        operator_symbol = OPERATOR_MAP[self.operator]
        if operator_symbol not in self.supported_operators:
            raise BadQueryException(
                f"The operator '{operator_symbol}' is not supported for the {self.field} field (use {self.allowed_operator_str()})."
            )
        return self.run()


class StringFilter(Filter):
    supported_operators = [":", "="]

    def run(self):
        return Q(**{f"{self.field}__{self.operator}": self.value})


class CveFilter(Filter):
    supported_operators = [":", "="]

    def run(self):
        return Q(**{f"cve_id__{self.operator}": self.value})


class CweFilter(Filter):
    supported_operators = [":"]

    def run(self):
        return Q(**{f"weaknesses__{self.operator}": self.value})


class CvssFilter(Filter):
    supported_operators = [">", ">=", "<", "<=", "="]

    def run(self):
        try:
            value = int(self.value)
        except ValueError:
            query_str = f"{self.field}{OPERATOR_MAP[self.operator]}{self.value}"
            raise BadQueryException(
                f"The value '{self.value}' in the query '{query_str}' is invalid (only integers are accepted)."
            )

        cvss_mapping = {
            "cvss20": "cvssV2_0",
            "cvss30": "cvssV3_0",
            "cvss31": "cvssV3_1",
            "cvss40": "cvssV4_0",
        }
        metric = cvss_mapping[self.field]

        return Q(**{f"metrics__{metric}__data__score__{self.operator}": value})


class KevFilter(Filter):
    supported_operators = [":"]

    def run(self):
        if self.value.lower() == "true":
            return Q(metrics__kev__data__dateAdded__isnull=False)
        elif self.value.lower() == "false":
            return Q(metrics__kev__data__dateAdded__isnull=True)
        else:
            raise BadQueryException("kev only supports true or false as value.")


class EpssFilter(Filter):
    supported_operators = [">", ">=", "<", "<=", "="]

    def run(self):
        try:
            value = float(self.value)
        except ValueError:
            raise BadQueryException(
                f"The EPSS value '{self.value}' is invalid (only numbers are accepted)."
            )

            # Validate that the value is between 0 and 100 (for percentage) or 0 and 1 (for decimal)
        if value < 0 or value > 100:
            raise BadQueryException(
                f"The EPSS value '{self.value}' is invalid (must be between 0 and 100)."
            )

        # Convert percentage to decimal if value is > 1
        if value > 1:
            value = value / 100

        return Q(**{f"metrics__epss__data__score__{self.operator}": value})


class VendorFilter(Filter):
    supported_operators = [":"]

    def run(self):
        safe_value = self.value.replace("\\", "\\\\")
        return Q(**{"vendors__contains": safe_value})


class ProductFilter(Filter):
    supported_operators = [":"]

    def run(self):
        # TODO: add a new column in CVEs table to improve performance
        # class Cve(BaseModel):
        #    products = models.JSONField(default=list)
        #
        # We will be able to use `contains` instead of `icontains`:
        #   Q(**{"products__contains": self.value)
        safe_value = self.value.replace("\\", "\\\\")
        return Q(**{"vendors__icontains": f"{PRODUCT_SEPARATOR}{safe_value}"})


class UserTagFilter(Filter):
    supported_operators = [":"]

    def run(self):
        if not self.user.is_authenticated:
            raise BadQueryException(
                "You must be logged in to use the 'userTag' filter."
            )

        try:
            UserTag.objects.get(name=self.value, user=self.user)
        except UserTag.DoesNotExist:
            raise BadQueryException(f"The tag '{self.value}' does not exist.")
        return Q(cve_tags__tags__contains=self.value, cve_tags__user=self.user)


class ProjectFilter(Filter):
    supported_operators = [":"]

    def run(self):
        if not self.user.is_authenticated:
            raise BadQueryException(
                "You must be logged in to use the 'project' filter."
            )

        try:
            project = Project.objects.get(
                name=self.value, organization=self.request.current_organization
            )
        except Project.DoesNotExist:
            raise BadQueryException(f"The project '{self.value}' does not exist.")

        # Get vendors and products from the project subscriptions
        vendors = project.subscriptions.get("vendors", [])
        products = project.subscriptions.get("products", [])
        all_keys = vendors + products

        if not all_keys:
            return Q(pk=None)

        return Q(vendors__has_any_keys=all_keys)


class Search:
    def __init__(self, q, request=None):
        self.q = q
        self.request = request
        self.user = self.request.user if self.request else None
        self._query = None
        self.error = None
        self.fields_count = 0

    @property
    def query(self):
        if not self._query:
            self._query = self.prepare_query()
        return self._query

    def increment_fields_count(self):
        self.fields_count = self.fields_count + 1
        if self.fields_count > settings.CVES_ADVANCED_SEARCH_MAX_FIELDS:
            raise MaxFieldsExceededException(
                f"To optimize results, the maximum number of fields that "
                f"can be searched is limited to {settings.CVES_ADVANCED_SEARCH_MAX_FIELDS}."
            )

    def validate_parsing(self):
        if not self.q:
            return True

        try:
            self.parse_jql(self.q)
            return True
        except pp.ParseException as e:
            self.error = e
            return False

    def prepare_query(self):
        if not self.q:
            return Cve.objects.order_by("-updated_at").all()

        parsed_query = self.parse_jql(self.q)
        json_filter = self.jql_to_json(parsed_query)
        q_query = self.json_to_django_q(json_filter)
        queryset = Cve.objects.filter(q_query).order_by("-updated_at")

        return queryset

    def json_to_django_q(self, filter_json):

        # Handle standalone value
        if (
            isinstance(filter_json, list)
            and len(filter_json) == 1
            and isinstance(filter_json[0], dict)
        ):
            filter_json = filter_json[0]

        if not isinstance(filter_json, dict):
            raise ValueError("Filter JSON must be a dictionary")

        if "$and" in filter_json:
            conditions = filter_json["$and"]
            if not isinstance(conditions, list):
                raise ValueError("$and must contain a list of conditions")
            return Q(*[self.json_to_django_q(c) for c in conditions], _connector=Q.AND)

        if "$or" in filter_json:
            conditions = filter_json["$or"]
            if not isinstance(conditions, list):
                raise ValueError("$or must contain a list of conditions")
            return Q(*[self.json_to_django_q(c) for c in conditions], _connector=Q.OR)

        q_objects = Q()

        filters_mapping = {
            "description": StringFilter,
            "title": StringFilter,
            "cvss20": CvssFilter,
            "cvss30": CvssFilter,
            "cvss31": CvssFilter,
            "cvss40": CvssFilter,
            "vendor": VendorFilter,
            "product": ProductFilter,
            "userTag": UserTagFilter,
            "cve": CveFilter,
            "cwe": CweFilter,
            "project": ProjectFilter,
            "kev": KevFilter,
            "epss": EpssFilter,
        }

        for field, filter in filter_json.items():

            if field not in filters_mapping.keys():
                raise BadQueryException(
                    f"The field '{field}' is not valid. Allowed fields are: {', '.join(filters_mapping.keys())}."
                )

            self.increment_fields_count()

            q_objects &= filters_mapping[field](
                field, filter["operator"], filter["value"], self.user, self.request
            ).execute()

        return q_objects

    def parse_jql(self, query):
        """
        Parse a JQL query and return a structured representation.
        """
        # Define grammar for parsing
        identifier = pp.Word(pp.alphanums + "_-")
        operator = pp.oneOf(": = != > < >= <=")
        value = pp.Word(pp.alphanums + "_-") | pp.quotedString.setParseAction(
            pp.removeQuotes
        )

        # Allow standalone words
        standalone = pp.Word(pp.alphanums + "_-")
        term = pp.Group(
            (identifier + operator + value)
            | standalone.setParseAction(self._single_fields)
        )

        # Operators for combining terms
        and_ = pp.CaselessKeyword("AND")
        or_ = pp.CaselessKeyword("OR")

        # Expressions for grouping
        expr = pp.infixNotation(
            term,
            [
                (and_, 2, pp.opAssoc.LEFT),
                (or_, 2, pp.opAssoc.LEFT),
            ],
        )

        # Parse the query
        parsed = expr.parseString(query, parseAll=True).asList()

        # Remove unnecessary outer list layer
        if len(parsed) == 1 and isinstance(parsed[0], list):
            return parsed[0]

        return parsed

    def _single_fields(self, tokens):
        """Handle standalone terms or empty queries by mapping to 'description' OR 'cve'."""
        term = tokens[0]

        if term.upper().startswith("CVE-"):
            return {"cve": {"operator": "exact", "value": term.upper()}}

        return {"description": {"operator": "icontains", "value": term}}

    def jql_to_json(self, parsed):
        if isinstance(parsed, list):
            if len(parsed) > 1 and parsed[1] in {"AND", "OR"}:
                logical_op = "$and" if parsed[1] == "AND" else "$or"
                return {logical_op: [self.jql_to_json(part) for part in parsed[::2]]}

            if len(parsed) == 3:
                field, operator, value = parsed
                return {
                    field: {
                        "operator": OPERATOR_MAP_BY_SYMBOL[operator],
                        "value": value,
                    }
                }

        return parsed
