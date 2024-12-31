from django.db.models import Q
import pyparsing as pp

from cves.models import Cve


class Search:
    def __init__(self, q, user=None):
        self.q = q
        self.user = user
        self._query = None
        self.error = None

    @property
    def query(self):
        if not self._query:
            self._query = self.prepare_query()
        return self._query

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
            return Cve.objects.all()

        print("Query => " + self.q)
        parsed_query = self.parse_jql(self.q)
        print("Parsed Query => " + str(parsed_query))
        json_filter = self.jql_to_json(parsed_query)
        print("Json Filter => " + str(json_filter))
        q_query = self.json_to_django_q(json_filter)
        print("Q Query => " + str(q_query))
        queryset = Cve.objects.filter(q_query).order_by("-updated_at")
        print("Queryset => " + str(queryset.query))
        return queryset

    def cvss_filter(self):
        pass

    def json_to_django_q(self, filter_json):
        """
        Convert a JSON filter with $and/$or syntax into a Django Q object.
        """
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

        for key, value in filter_json.items():
            if isinstance(value, dict):
                for operator, val in value.items():
                    if operator == "gt":
                        q_objects &= Q(**{f"metrics__{key}__data__score__gt": int(val)})
                    elif operator == "gte":
                        q_objects &= Q(
                            **{f"metrics__{key}__data__score__gte": int(val)}
                        )
                    elif operator == "lt":
                        q_objects &= Q(**{f"metrics__{key}__data__score__lt": int(val)})
                    elif operator == "lte":
                        q_objects &= Q(
                            **{f"metrics__{key}__data__score__lte": int(val)}
                        )
                    elif operator == "exact":
                        q_objects &= Q(
                            **{f"metrics__{key}__data__score__exact": int(val)}
                        )
                    elif operator == "icontains":
                        q_objects &= Q(**{f"{key}__icontains": val})
            else:
                q_objects &= Q(**{f"{key}__icontains": value})

        return q_objects

    def parse_jql(self, query):
        """
        Parse a JQL query and return a structured representation.

        :param query: The JQL query string.
        :return: A structured representation of the query.
        """
        # Define grammar for parsing
        identifier = pp.Word(pp.alphanums + "_-")
        operator = pp.oneOf(": = != > < >= <=")
        value = pp.Word(pp.alphanums + "_-") | pp.quotedString.setParseAction(
            pp.removeQuotes
        )

        term = pp.Group(identifier + operator + value)

        # Operators for combining terms
        and_ = pp.CaselessKeyword("AND")
        or_ = pp.CaselessKeyword("OR")

        # Expressions for grouping
        expr = pp.infixNotation(
            term,
            [
                (and_, 2, pp.opAssoc.LEFT),  # AND is binary
                (or_, 2, pp.opAssoc.LEFT),  # OR is binary
            ],
        )

        # Parse the query
        parsed = expr.parseString(query, parseAll=True).asList()

        # Remove unnecessary outer list layer if needed
        if len(parsed) == 1 and isinstance(parsed[0], list):
            return parsed[0]

        return parsed

    def jql_to_json(self, parsed):
        """
        Convert a parsed JQL structure into a JSON-compatible filter format.
        """
        if isinstance(parsed, list):
            # Handle logical operators (AND, OR)
            if len(parsed) > 1 and parsed[1] in {"AND", "OR"}:
                logical_op = "$and" if parsed[1] == "AND" else "$or"
                return {logical_op: [self.jql_to_json(part) for part in parsed[::2]]}

            # Handle simple conditions
            if len(parsed) == 3:
                field, operator, value = parsed
                operator_map = {
                    ">": "gt",
                    ">=": "gte",
                    "<": "lt",
                    "<=": "lte",
                    "=": "exact",
                    ":": "icontains",
                }
                return {field: {operator_map[operator]: value}}

        # Return as-is if the input is atomic (e.g., a string)
        return parsed
