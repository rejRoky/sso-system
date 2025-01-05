from django.db import models


# Create your models here.

class FooterMultipleLogo(models.Model):
    footer_logo = models.ImageField(upload_to='footer_logo/')
    footer_logo_status = models.BooleanField(default=True)

    def __str__(self):
        return


class SiteSetting(models.Model):
    site_name = models.CharField(max_length=100, null=True, blank=True)
    site_logo = models.ImageField(upload_to='site_logo/', null=True, blank=True)
    site_favicon = models.ImageField(upload_to='site_favicon/', null=True, blank=True)
    site_title = models.CharField(max_length=100, null=True, blank=True)
    site_footer_logo = models.ForeignKey(FooterMultipleLogo, on_delete=models.CASCADE, null=True, blank=True)

    site_email = models.EmailField(null=True, blank=True)
    site_phone = models.CharField(max_length=20, null=True, blank=True)
    site_address = models.TextField(null=True, blank=True)

    site_facebook = models.URLField(null=True, blank=True)
    site_linkedin = models.URLField(null=True, blank=True)
    site_youtube = models.URLField(null=True, blank=True)
    site_whatsapp = models.URLField(null=True, blank=True)
    site_map = models.TextField(null=True, blank=True)
    site_status = models.BooleanField(default=True)

    def __str__(self):
        return self.site_name
