from django.contrib import admin
from .models import User, UserActionLog, UserGroup

admin.site.register(User)

class UserActionLogAdmin(admin.ModelAdmin):
    list_display = ['user', 'action_type', 'timestamp', 'ip_address']
    search_fields = ['user__mobile_number', 'action_type', 'action_description']
    list_filter = ['action_type', 'timestamp']

admin.site.register(UserActionLog, UserActionLogAdmin)

@admin.register(UserGroup)
class UserGroupAdmin(admin.ModelAdmin):
    list_display = ['name', 'description', 'created_at', 'updated_at']
    search_fields = ['name', 'description']
    list_filter = ['created_at', 'updated_at']
