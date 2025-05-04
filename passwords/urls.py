from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    RegisterUserView,
    PasswordEntryViewSet,
    VerifyOTPView,
    Enable2FAView,
    Disable2FAView,
    GenerateQRView,
    DecryptPasswordView,
    ChangePasswordView,
    GeneratePasswordView,
    CustomLoginView,
    ExportPasswordsView,
    ImportPasswordsView,
    LoadFernetKeyView
)

# Роутер для управления паролями
router = DefaultRouter()
router.register(r'passwords', PasswordEntryViewSet)

# Основные маршруты API
urlpatterns = [
    path('register/', RegisterUserView.as_view(), name='register'),
    path('', include(router.urls)),  # CRUD для паролей
    path('login/', CustomLoginView.as_view(), name='login'),
    path('load-fernet-key/', LoadFernetKeyView.as_view(), name='master_password'),

    # Управление паролями
    path('decrypt-password/', DecryptPasswordView.as_view(), name='decrypt_password'),
    path('generate-password/', GeneratePasswordView.as_view(), name='generate_password'),
    path('change-password/', ChangePasswordView.as_view(), name='change_password'),

    # Двухфакторная аутентификация
    path('verify-otp/', VerifyOTPView.as_view(), name='verify_otp'),
    path('enable-2fa/', Enable2FAView.as_view(), name='enable_2fa'),
    path('disable-2fa/', Disable2FAView.as_view(), name='disable_2fa'),
    path('generate-qr/', GenerateQRView.as_view(), name='generate_qr'),

    # Импорт и экспорт паролей
    path('export-passwords/', ExportPasswordsView.as_view(), name='export_passwords'),
    path('import-passwords/', ImportPasswordsView.as_view(), name='import_passwords'),
]
