from rest_framework import generics
from .models import FooterMultipleLogo, SiteSetting
from .serializers import FooterMultipleLogoSerializer, SiteSettingSerializer

class SiteSettingListView(generics.ListAPIView):
    queryset = SiteSetting.objects.all()
    serializer_class = SiteSettingSerializer

class SiteSettingDetailView(generics.RetrieveAPIView):
    queryset = SiteSetting.objects.all()
    serializer_class = SiteSettingSerializer

class FooterMultipleLogoListView(generics.ListAPIView):
    queryset = FooterMultipleLogo.objects.all()
    serializer_class = FooterMultipleLogoSerializer

class FooterMultipleLogoDetailView(generics.RetrieveAPIView):
    queryset = FooterMultipleLogo.objects.all()
    serializer_class = FooterMultipleLogoSerializer
