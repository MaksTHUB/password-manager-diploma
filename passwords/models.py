from django.contrib.auth.models import AbstractUser
from django.db import models
from django.conf import settings
from datetime import timedelta
from django.utils.timezone import now
import pyotp
from passwords import fernet_key



# Extended user model with 2FA support
class UserProfile(AbstractUser):
    otp_secret = models.CharField(max_length=32, blank=True, null=True)  # ✅ Разрешаем NULL
    is_2fa_enabled = models.BooleanField(default=False)
    otp_attempts = models.IntegerField(default=0)
    otp_locked_until = models.DateTimeField(null=True, blank=True)
    failed_login_attempts = models.IntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    master_attempts = models.IntegerField(default=0)
    master_locked_until = models.DateTimeField(null=True, blank=True)


    # Generates an OTP code if 2FA is enabled
    def generate_otp(self):
        return pyotp.TOTP(self.otp_secret).now() if self.is_2fa_enabled else None

    # Checks the entered OTP code
    def verify_otp(self, otp):
        if not self.is_2fa_enabled:
            return False  

        # We will unblock the user if the lock has expired
        if self.otp_locked_until and self.otp_locked_until <= now():
            self.otp_attempts = 0
            self.otp_locked_until = None
            self.save()

        # If 2FA is blocked, we reject the verification
        if self.otp_locked_until and self.otp_locked_until > now():
            return False  

        # Checking the OTP code
        totp = pyotp.TOTP(self.otp_secret)
        if totp.verify(otp, valid_window=2):
            self.otp_attempts = 0
            self.otp_locked_until = None
            self.save()
            return True
        else:
            self.otp_attempts += 1
            if self.otp_attempts >= 5:
                self.otp_locked_until = now() + timedelta(minutes=5)
            self.save()
            return False

    # Checks if the user is blocked
    def is_locked(self):
        return self.locked_until and self.locked_until > now()


# Encrypted Password Storage Model
class PasswordEntry(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    website = models.CharField(max_length=255)
    username = models.CharField(max_length=255)
    password = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Encrypts the password if it is not encrypted yet
    def encrypt_password(self, raw_password):
        fernet = fernet_key.current_fernet
        if not fernet:
            raise Exception("Fernet key is not loaded")
        if raw_password.startswith("gAAAAA"):
            return raw_password
        return fernet.encrypt(raw_password.encode()).decode()


    # Decrypts the password
    def decrypt_password(self): 
        fernet = fernet_key.current_fernet
        try:
            return fernet.decrypt(self.password.encode()).decode()
        except Exception:
            return "Decryption error"


    # Encrypts the password before saving, if it is not encrypted yet.
    def save(self, *args, **kwargs):
        if self.password and not self.password.startswith("gAAAAA"):
            self.password = self.encrypt_password(self.password)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.website} ({self.username})"
