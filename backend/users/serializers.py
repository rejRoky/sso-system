from rest_framework import serializers
from .models import User, UserGroup


class UserSerializer(serializers.ModelSerializer):

    office = serializers.CharField(source='office.name_Bn', read_only=True)

    class Meta:
        model = User
        fields =  ['id', 'mobile_number', 'full_name', 'email', 'office', 'designation', 'address', 'is_active', 'is_staff', 'is_superuser','profile_picture', 'role', 'created_at', 'updated_at']





class UserGroupSerializer(serializers.ModelSerializer):
    annotation_name = serializers.CharField(source='annotation.name', read_only=True)
    users_detail = UserSerializer(many=True, read_only=True, source='users')
    class Meta:
        model = UserGroup
        fields = ['id', 'name', 'description', 'annotation', 'annotation_name', 'created_at', 'updated_at', 'users_detail', 'users']