from pathlib import Path
from datetime import timedelta


# Определяем базовую директорию проекта
BASE_DIR = Path(__file__).resolve().parent.parent       

# Секретный ключ
SECRET_KEY = "django-insecure-$7*8f22ect2km=b09k$16^!t==+mj2(cbs51w%23u%qvb1-aek"


# Включен режим отладки (для разработки)
DEBUG = True

# Разрешенные хосты
ALLOWED_HOSTS = []

SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False

# Установленные приложения
INSTALLED_APPS = [
    # 'django.contrib.admin',  # Пока админка не нужна
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'drf_yasg',  # Документация API
    'rest_framework',
    'passwords',  # Основное приложение
    'django_extensions',
]

# Используем кастомную модель пользователя
AUTH_USER_MODEL = 'passwords.UserProfile'

# Middleware (прослойки обработки запросов)
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# Файлы маршрутизации
ROOT_URLCONF = 'password_manager.urls'

# Настройки шаблонов
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / "templates"],  
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

# WSGI-приложение
WSGI_APPLICATION = 'password_manager.wsgi.application'

# Настройки базы данных (по умолчанию SQLite)
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Валидация паролей
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# Локализация
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Статические файлы
STATIC_URL = 'static/'

# Настройки REST API
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
}

# JWT-токены
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(days=1),  
    'REFRESH_TOKEN_LIFETIME': timedelta(seconds=0),  
}


# Swagger-документация
SWAGGER_SETTINGS = {
    'DEFAULT_INFO': 'password_manager.urls.api_info',
    'SECURITY_DEFINITIONS': {
        'Bearer': {
            'type': 'apiKey',
            'name': 'Authorization',
            'in': 'header'
        }
    },
}





