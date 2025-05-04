from django.contrib.auth import get_user_model
from .models import PasswordEntry
from rest_framework import serializers
from passwords import fernet_key
from passwords.common_passwords_list import is_common_password


User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)
    master_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ["id", "username", "password", "confirm_password", "master_password"]
        extra_kwargs = {"password": {"write_only": True}}

    # Проверка самого пароля
    def validate_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        if len(value) > 64:
            raise serializers.ValidationError("Password must not exceed 64 characters.")
        if is_common_password(value.lower()):
            raise serializers.ValidationError("This password is too common. Please choose a more secure one.")
        return value

    # Проверка совпадения паролей
    def validate(self, data):
        if data["password"] != data["confirm_password"]:
            raise serializers.ValidationError("The passwords don't match")
        return data

    # Создание пользователя
    def create(self, validated_data):
        validated_data.pop("confirm_password")  # Убираем перед сохранением
        validated_data.pop("master_password")   # Не нужен для модели
        return User.objects.create_user(**validated_data)



class MasterPasswordSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    master_password = serializers.CharField(required=True)



class PasswordEntrySerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = PasswordEntry
        fields = ["id", "website", "username", "password", "created_at", "updated_at"]

    # Checks the password length before saving
    def validate_password(self, value):
        if not (8 <= len(value) <= 64):
            raise serializers.ValidationError("The password must be between 8 and 64 characters long")
        return value

    # Encrypts the password before saving
    def create(self, validated_data):
        fernet = fernet_key.current_fernet
        if not fernet:
            raise Exception("Fernet key is not loaded")
        validated_data["password"] = fernet.encrypt(validated_data["password"].encode()).decode()
        return super().create(validated_data)



class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True, help_text="old password")
    new_password = serializers.CharField(required=True, help_text="new password")

    def validate_new_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError("The password must contain at least 8 characters")
        if len(value) > 64:
            raise serializers.ValidationError("The password must not exceed 64 characters")
        if is_common_password(value.lower()):
            raise serializers.ValidationError("This password is too common. Please choose a more secure one.")
        return value



class IDSerializer(serializers.Serializer):
    id = serializers.IntegerField(help_text="ID of the record to decrypt")


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True, help_text="username")
    password = serializers.CharField(required=True, help_text="password", style={"input_type": "password"})


class VerifyOTPSerializer(serializers.Serializer):
    username = serializers.CharField(required=True, help_text="username")
    otp = serializers.CharField(required=True, help_text="otp")

class ExportPasswordSerializer(serializers.Serializer):
    master_password = serializers.CharField(required=True, help_text="Master password for export")
