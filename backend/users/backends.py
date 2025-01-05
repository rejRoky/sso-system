from django.contrib.auth.backends import ModelBackend
from .models import User


class MobileNumberBackend(ModelBackend):
    def authenticate(self, request, mobile_number=None, password=None, **kwargs):
        try:
            user = User.objects.get(mobile_number=mobile_number)
            if user.check_password(password):
                return user
        except User.DoesNotExist:
            return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
