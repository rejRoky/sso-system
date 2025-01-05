from django.urls import path
from . import views

urlpatterns = [
    path('site-settings/', views.SiteSettingListView.as_view(), name='site-settings-list'),
    path('site-settings/<int:pk>/', views.SiteSettingDetailView.as_view(), name='site-settings-detail'),
    path('site-settings/footer-logo/', views.FooterMultipleLogoListView.as_view(), name='footer-logos-list'),
    path('site-settings/footer-logo/<int:pk>/', views.FooterMultipleLogoDetailView.as_view(), name='footer-logos-detail'),
]
