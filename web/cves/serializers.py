from rest_framework import serializers

from cves.models import Cve, Product, Vendor, Weakness


class DateTimeWithoutMicrosecondsField(serializers.DateTimeField):
    """DateTime field that serializes without microseconds."""

    def to_representation(self, value):
        if value is None:
            return None
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")


class CveListSerializer(serializers.ModelSerializer):
    created_at = DateTimeWithoutMicrosecondsField(read_only=True)
    updated_at = DateTimeWithoutMicrosecondsField(read_only=True)

    class Meta:
        model = Cve
        fields = ["created_at", "updated_at", "cve_id", "description"]


class CveDetailSerializer(serializers.ModelSerializer):
    created_at = DateTimeWithoutMicrosecondsField(read_only=True)
    updated_at = DateTimeWithoutMicrosecondsField(read_only=True)

    class Meta:
        model = Cve
        fields = [
            "created_at",
            "updated_at",
            "cve_id",
            "title",
            "description",
            "metrics",
            "weaknesses",
            "vendors",
        ]


class WeaknessListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Weakness
        fields = [
            "created_at",
            "updated_at",
            "cwe_id",
        ]


class VendorListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vendor
        fields = [
            "id",
            "created_at",
            "updated_at",
            "name",
        ]


class ProductListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = [
            "id",
            "created_at",
            "updated_at",
            "name",
        ]
