from django.urls import path, include
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

# Настройка Swagger-документации
schema_view = get_schema_view(
    openapi.Info(
        title="Password Manager API",
        default_version='v1',
        description="API для менеджера паролей",
        contact=openapi.Contact(email="support@example.com"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path('api/', include('passwords.urls')),  # Основные API маршруты
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='swagger-ui'),  # Документация Swagger
]
