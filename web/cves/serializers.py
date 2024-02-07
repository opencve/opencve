from rest_framework import serializers

from cves.models import Cve, Product, Vendor, Weakness


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
            "weaknesses",
            "vendors",
            "mitre_json",
            "nvd_json",
        ]


class CweListSerializer(serializers.ModelSerializer):
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
