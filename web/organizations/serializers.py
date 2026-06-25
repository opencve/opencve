from rest_framework import serializers

from organizations.models import Organization


class OrganizationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = [
            "id",
            "created_at",
            "updated_at",
            "name",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]


class OrganizationDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = ["id", "created_at", "updated_at", "name"]
        read_only_fields = ["id", "created_at", "updated_at"]
