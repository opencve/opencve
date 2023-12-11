from rest_framework import serializers

from cves.models import Cve, Cwe, Product, Vendor


class CveListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Cve
        fields = ["created_at", "updated_at", "cve_id", "summary"]


class CveDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = Cve
        fields = [
            "created_at",
            "updated_at",
            "cve_id",
            "summary",
            "cvss",
            "cwes",
            "vendors",
            "mitre_json",
            "nvd_json",
        ]


class CweListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Cwe
        fields = ["created_at", "updated_at", "cwe_id",]


class VendorListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vendor
        fields = ["id", "created_at", "updated_at", "name",]


class ProductListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = ["id", "created_at", "updated_at", "name",]
