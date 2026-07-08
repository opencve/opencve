from drf_spectacular.utils import OpenApiParameter
from rest_framework.pagination import PageNumberPagination as DrfPageNumberPagination


class PageNumberPagination(DrfPageNumberPagination):
    page_size = 20
    page_size_query_param = "page_size"
    max_page_size = 100
    page_size_query_description = (
        "Number of results to return per page (default: 20, maximum: 100)."
    )

    def get_schema_operation_parameters(self, view):
        parameters = super().get_schema_operation_parameters(view)
        for param in parameters:
            if param.get("name") == self.page_size_query_param:
                param["description"] = self.page_size_query_description
                param["schema"] = {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": self.max_page_size,
                }
                break
        return parameters

    def get_paginated_response_schema(self, schema):
        response = super().get_paginated_response_schema(schema)
        response["properties"]["count"]["example"] = 1
        response["properties"]["next"]["example"] = None
        response["properties"]["previous"]["example"] = None
        return response


def pagination_openapi_parameters():
    """OpenAPI query parameters for paginated endpoints."""
    paginator = PageNumberPagination()
    parameters = []

    for param in paginator.get_schema_operation_parameters(view=None):
        parameters.append(
            OpenApiParameter(
                name=param["name"],
                type=int,
                location=OpenApiParameter.QUERY,
                required=param.get("required", False),
                description=param.get("description", ""),
            )
        )

    return parameters
