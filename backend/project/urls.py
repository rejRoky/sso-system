from django.contrib import admin
from django.urls import path, include, re_path
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from django.conf import settings
from django.conf.urls.static import static
from rest_framework_simplejwt.authentication import JWTAuthentication


# Define the schema view
schema_view = get_schema_view(
    openapi.Info(
        title="Data-Management-Platform-System API",
        default_version="v1",
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
    authentication_classes=[JWTAuthentication],
)

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", include("users.urls")),
    path('api/', include('sitesetting.urls')),
    path('api/', include('annotation.urls')),
    re_path(r"doc/$", schema_view.with_ui("swagger", cache_timeout=0), name="schema-swagger-ui"),
    re_path(r"redoc/$", schema_view.with_ui("redoc", cache_timeout=0), name="schema-redoc"),
    path("ckeditor/", include("ckeditor_uploader.urls")),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
