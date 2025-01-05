from os.path import split

from django.utils.timezone import now
from .models import UserActionLog

class UserActionLoggerMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        if request.user.is_authenticated:
            # Capture the user's IP address
            ip_address = request.META.get('HTTP_X_FORWARDED_FOR')
            if ip_address:
                ip_address = ip_address.split(',')[0]  # Get the first IP if there are multiple
            else:
                ip_address = request.META.get('REMOTE_ADDR', '0.0.0.0')

            # Create a log entry for the action
            UserActionLog.objects.create(
                user=request.user,
                action_type= f'{request.method} {split(request.path)[0]}',
                action_description=f"{request.user} accessed {request.path}",
                ip_address=ip_address,
                timestamp=now()
            )
        return response
