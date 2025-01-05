from django.contrib import admin
from .models import FooterMultipleLogo, SiteSetting

# Register your models here.

@admin.register(FooterMultipleLogo)
class FooterMultipleLogoAdmin(admin.ModelAdmin):
    list_display = ('id', 'footer_logo', 'footer_logo_status')
    list_filter = ('footer_logo_status',)
    search_fields = ('id',)

@admin.register(SiteSetting)
class SiteSettingAdmin(admin.ModelAdmin):
    list_display = ('site_name', 'site_email', 'site_phone', 'site_status')
    list_filter = ('site_status',)
    search_fields = ('site_name', 'site_email', 'site_phone')
