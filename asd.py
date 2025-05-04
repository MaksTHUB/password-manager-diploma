""" from cryptography.fernet import Fernet

# Генерация и вывод ключа
key = Fernet.generate_key()
print(key.decode())
 """


""" import datetime

print(f"Серверное время: {datetime.datetime.now()}") """

import os
import django

# Загружаем настройки Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "password_manager.settings")
django.setup()

from cryptography.fernet import Fernet
from django.conf import settings

cipher = Fernet(settings.FERNET_KEY)

encrypted_password = b"gAAAAABn2sM6WdvlsXEJwa2biNisTJ3X3GkOaBfjsV7j4NpfMBeAOYtKjriqZMXHV9Vn491wiSllbxz7QROBr0ZX-5xADQhfqAdyQ8-JVyEJ-ieiY1LzVJem55gst1YSB16Vpe-9afsbqgmc73fFfMIUiRHv42w5vfYpLLss1TyDFxGnHo1ghOSZcKzuLk8rJROpxbFZcuX4VGsLrWRJXEyH7NCOKTKgqW-P1hqlGCWooMzL6ntTXns="

try:
    decrypted = encrypted_password.decode()  # ✅ Приводим bytes к str
    count = 0

    while decrypted.startswith("gAAAAA"):  # ✅ Теперь это строка, и ошибка исчезнет
        decrypted = cipher.decrypt(decrypted.encode()).decode()
        count += 1
        print(f"{count}-я расшифровка: {decrypted}")

    print("✅ Финальный пароль:", decrypted)
    print("🔢 Пароль был зашифрован:", count, "раз(а)")
except Exception as e:
    print("❌ Ошибка расшифровки:", str(e))


""" import os
import django

# Указываем путь к settings.py
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "password_manager.settings")
django.setup()

from passwords.models import UserProfile
from pyotp import TOTP

user = UserProfile.objects.get(id=1)
totp = TOTP(user.otp_secret)

otp_correct = totp.verify("188145")
print("✅ Верный ли OTP?", otp_correct)
 """
""" from django.conf import settings
print("FERNET_KEY:", settings.FERNET_KEY)  # Проверка в консоли """
