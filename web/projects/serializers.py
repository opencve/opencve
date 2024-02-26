from rest_framework import serializers

from cves.constants import PRODUCT_SEPARATOR
from projects.models import Project


class ProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = Project
        fields = [
            "id",
            "created_at",
            "updated_at",
            "name",
            "description",
        ]


class ProjectDetailSerializer(serializers.ModelSerializer):
    subscriptions = serializers.SerializerMethodField()

    class Meta:
        model = Project
        fields = [
            "id",
            "created_at",
            "updated_at",
            "name",
            "description",
            "subscriptions",
        ]

    @staticmethod
    def get_subscriptions(instance):
        subscriptions = {"vendors": instance.subscriptions["vendors"], "products": {}}
        for product in instance.subscriptions["products"]:
            v_name, p_name = product.split(PRODUCT_SEPARATOR)
            if v_name not in subscriptions["products"]:
                subscriptions["products"][v_name] = []
            subscriptions["products"][v_name].append(p_name)
        return subscriptions
