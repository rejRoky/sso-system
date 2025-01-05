from django.db.models.signals import post_save
from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver
from django.utils.timezone import now
from .models import User, UserActionLog
from django.contrib.auth.signals import user_logged_out

# # Signal for user login
# @receiver(user_logged_in)
# def log_user_login(sender, request, user, **kwargs):
#     UserActionLog.objects.create(
#         user=user,
#         action_type='LOGIN',
#         ip_address=request.META.get('REMOTE_ADDR', 'Unknown'),
#         action_description=f"User logged in from IP: {request.META.get('REMOTE_ADDR', 'Unknown')}",
#         timestamp=now()
#     )
#
# # Signal for user registration
# @receiver(post_save, sender=User)
# def log_user_registration(sender, instance, created, **kwargs):
#     if created:
#         UserActionLog.objects.create(
#             user=instance,
#             action_type='REGISTER',
#             action_description=f"User registered with mobile number: {instance.mobile_number}",
#             timestamp=now()
#         )
#
# # Signal for user profile update
# @receiver(post_save, sender=User)
# def log_user_profile_update(sender, instance, created, update_fields, **kwargs):
#     if not created:
#         updated_fields = ', '.join(update_fields) if update_fields else 'Unknown fields'
#         UserActionLog.objects.create(
#             user=instance,
#             action_type='UPDATE',
#             action_description=f"User updated fields: {updated_fields}",
#             timestamp=now()
#         )
#
# # Signal for user logout
# @receiver(user_logged_out)
# def log_user_logout(sender, request, user, **kwargs):
#     UserActionLog.objects.create(
#         user=user,
#         action_type='LOGOUT',
#         ip_address=request.META.get('REMOTE_ADDR', 'Unknown'),
#         action_description=f"User logged out from IP: {request.META.get('REMOTE_ADDR', 'Unknown')}",
#         timestamp=now()
#    )
