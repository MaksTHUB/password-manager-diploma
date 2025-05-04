import django
import os

# Указываем Django-проект
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "password_manager.settings")
django.setup()

from passwords.models import UserProfile

def unlock_user(username):
    try:
        user = UserProfile.objects.get(username=username)
        user.failed_login_attempts = 0  # ✅ Обнуляем попытки
        user.locked_until = None  # ✅ Убираем блокировку
        user.save()
        print(f"✅ Пользователь '{username}' успешно разблокирован! Теперь у него 5 новых попыток.")
    except UserProfile.DoesNotExist:
        print(f"❌ Пользователь '{username}' не найден.")

if __name__ == "__main__":
    username = input("Введите имя пользователя для разблокировки: ")
    unlock_user(username)
