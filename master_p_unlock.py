import os
import django
from datetime import timedelta

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "password_manager.settings")
django.setup()

from passwords.models import UserProfile

def reset_master_lock(username):
    try:
        user = UserProfile.objects.get(username=username)
        user.master_attempts = 0
        user.master_locked_until = None
        user.save()
        print(f"✅ Мастер-блокировка для '{username}' успешно снята. Попытки обнулены.")
    except UserProfile.DoesNotExist:
        print(f"❌ Пользователь '{username}' не найден.")

if __name__ == "__main__":
    username = input("Введите имя пользователя для сброса блокировки мастер-пароля: ")
    reset_master_lock(username)
