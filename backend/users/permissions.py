from rest_framework import permissions


class IsOwnProfileOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow users to edit their own profile.
    """

    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request.
        if request.method in permissions.SAFE_METHODS:
            return True

        # Write permissions are only allowed to the user who owns the profile.
        return obj == request.user
