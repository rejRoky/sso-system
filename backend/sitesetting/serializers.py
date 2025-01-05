from rest_framework import serializers
from .models import FooterMultipleLogo, SiteSetting

class FooterMultipleLogoSerializer(serializers.ModelSerializer):
    class Meta:
        model = FooterMultipleLogo
        fields = ['id', 'footer_logo', 'footer_logo_status']

class SiteSettingSerializer(serializers.ModelSerializer):
    class Meta:
        model = SiteSetting
        fields = [
            'site_name', 'site_logo', 'site_favicon', 'site_title', 'site_footer_logo',
            'site_email', 'site_phone', 'site_address',
            'site_facebook', 'site_linkedin', 'site_youtube', 'site_whatsapp', 'site_map',
            'site_status'
        ]
