from django.core.management.base import BaseCommand
from passwords.models import UserProfile

class Command(BaseCommand):
    help = "Сбрасывает блокировку OTP у пользователя"

    def add_arguments(self, parser):
        parser.add_argument("username", type=str, help="Имя пользователя")

    def handle(self, *args, **kwargs):
        username = kwargs["username"]
        
        try:
            user = UserProfile.objects.get(username=username)
            user.otp_attempts = 0  # Обнуляем попытки
            user.otp_locked_until = None  # Убираем блокировку
            user.save()  # Сохраняем изменения
            print(f"Блокировка снята для {username}")
        except UserProfile.DoesNotExist:
            print(f"Пользователь {username} не найден")
