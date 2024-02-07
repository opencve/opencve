from rest_framework import serializers

from changes.models import Change, Report


class ChangeSerializer(serializers.ModelSerializer):
    cve = serializers.StringRelatedField()

    class Meta:
        model = Change
        fields = [
            "id",
            "created_at",
            "updated_at",
            "path",
            "commit",
            "cve",
        ]


class ReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = Report
        fields = [
            "id",
            "created_at",
            "updated_at",
            "day",
            "seen",
        ]


class ReportDetailSerializer(serializers.ModelSerializer):
    changes = ChangeSerializer(read_only=True, many=True)

    class Meta:
        model = Report
        fields = ["id", "created_at", "updated_at", "day", "seen", "changes"]
