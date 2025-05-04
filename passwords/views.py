import qrcode
import io
import base64
import pyotp
import hmac
import random
import string
import json
import hashlib
import os
from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework.permissions import IsAuthenticated
from rest_framework import generics, viewsets
from rest_framework.response import Response
from rest_framework.views import APIView
from django.core.cache import cache
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.hashers import check_password, make_password
from django.utils.timezone import now
from django.http import JsonResponse
from drf_yasg.utils import swagger_auto_schema
from datetime import timedelta
from .serializers import UserSerializer, PasswordEntrySerializer, ChangePasswordSerializer, IDSerializer, LoginSerializer, VerifyOTPSerializer, MasterPasswordSerializer, ExportPasswordSerializer
from .models import PasswordEntry, UserProfile
from passwords import fernet_key  # для изменения значения переменной
from passwords.common_passwords_list import is_common_password 


User = get_user_model()



# User registration
class RegisterUserView(generics.CreateAPIView):
    
    serializer_class = UserSerializer
    @swagger_auto_schema(request_body=UserSerializer)
    def post(self, request, *args, **kwargs):
        master_password = request.data.get("master_password")
        if not master_password:
            return Response({"error": "Master password is required"}, status=400)

        response = super().post(request, *args, **kwargs)

        if response.status_code == 201:
            fernet_key = Fernet.generate_key()
            encrypt_fernet_key(master_password, fernet_key)

        return response



def encrypt_fernet_key(master_password: str, fernet_key: bytes, file_path=".env.enc"):

    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    derived_key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    fernet = Fernet(derived_key)

    encrypted = fernet.encrypt(fernet_key)

    with open(file_path, "wb") as f:
        f.write(salt + encrypted)



def load_fernet_key(master_password: str, file_path=".env.enc") -> Fernet:

    with open(file_path, "rb") as f:
        content = f.read()

    salt = content[:16]
    encrypted_key = content[16:]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    derived_key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    fernet = Fernet(derived_key)

    decrypted_key = fernet.decrypt(encrypted_key)
    return Fernet(decrypted_key)



def load_all_fernet_keys(master_password: str, keys_path=".keys.enc", current_key=None) -> MultiFernet:
    if not os.path.exists(keys_path):
        return MultiFernet([current_key]) if current_key else None

    with open(keys_path, "rb") as f:
        content = f.read()

    salt = content[:16]
    encrypted_data = content[16:]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    derived_key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    fernet = Fernet(derived_key)

    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except Exception:
        raise ValueError("Unable to decrypt .keys.enc — check master password.")

    # Decoding the list of keys (via json or string)
    fernet_keys = json.loads(decrypted_data.decode())
    key_objects = [Fernet(k) for k in fernet_keys]

    if current_key and current_key not in key_objects:
        key_objects.insert(0, current_key)  # The current key is the first one

    return MultiFernet(key_objects)


class LoadFernetKeyView(APIView):
    @swagger_auto_schema(request_body=MasterPasswordSerializer)
    def post(self, request):
        master_password = request.data.get("master_password")
        username = request.data.get("username")

        if not master_password or not username:
            return Response({"error": "Username and master password are required"}, status=400)

        user = UserProfile.objects.filter(username=username).first()
        if not user:
            return Response({"error": "User not found"}, status=404)

        if user.master_locked_until and user.master_locked_until > now():
            return Response({"error": "Too many attempts. Try again later"}, status=403)

        try:
            # Uploading the current key
            current = load_fernet_key(master_password)
            fernet_key.current_fernet = MultiFernet([current])  # first, only the current one

            # Downloading all the old keys
            try:
                fernet_key.current_fernet = load_all_fernet_keys(master_password, current_key=current)
            except Exception as e:
                print(f"[warn] Failed to load all keys: {str(e)}")

            # we save the master password in memory for further export
            fernet_key.current_password = master_password
            print("[info] Master password saved in memory")

        except Exception:
            user.master_attempts += 1
            if user.master_attempts >= 5:
                user.master_locked_until = now() + timedelta(minutes=5)
            user.save()
            return Response({"error": "Incorrect master password"}, status=400)

        # Reset locks after successful authorization
        user.master_attempts = 0
        user.master_locked_until = None
        user.save()

        if not cache.get(f"auth_ready_{user.username}"):
            return Response({"error": "You must login or pass through 2FA first"}, status=403)

        # debug: we display all the uploaded keys
        if isinstance(fernet_key.current_fernet, MultiFernet):
            print("[debug] Loaded MultiFernet with", len(fernet_key.current_fernet._fernets), "keys")
            for i, f in enumerate(fernet_key.current_fernet._fernets):
                raw = f._signing_key + f._encryption_key
                print(f"[key {i+1}] {base64.urlsafe_b64encode(raw).decode()}")
        else:
            print("[debug] Loaded single Fernet key")

        access = AccessToken.for_user(user)
        cache.delete(f"auth_ready_{user.username}")
        return Response({"access": str(access)}, status=200)






# CRUD for password management
class PasswordEntryViewSet(viewsets.ModelViewSet):
    
    queryset = PasswordEntry.objects.all()
    permission_classes = [IsAuthenticated]
    serializer_class = PasswordEntrySerializer

    # Returns passwords of an authenticated user only
    def get_queryset(self):
        if not self.request.user.is_authenticated:
            return PasswordEntry.objects.none()  # Returns an empty QuerySet for anonymous users
        return PasswordEntry.objects.filter(user=self.request.user)
    
    # Binds the record to the current user
    def perform_create(self, serializer):
        serializer.save(user=self.request.user)



# Enables two-factor authentication (2FA)
class Enable2FAView(APIView):
    
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user

        if user.is_2fa_enabled:
            return Response({"error": "2FA is already enabled"}, status=400)
        request.user.is_2fa_enabled = True

        request.user.save()
        return Response({'message': '2FA is enabled'})



# Отключает 2FA 
class Disable2FAView(APIView):
    
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user

        if not user.is_2fa_enabled:
            return Response({"error": "2FA is already disabled"}, status=400)

        # Отключаем 2FA
        user.is_2fa_enabled = False
        user.otp_secret = None  # Удаляем секретный ключ
        user.save()

        return Response({"message": "2FA has been successfully disabled"})



# Generates a QR code for 2FA connection
class GenerateQRView(APIView):
    
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        if not user.otp_secret:
            user.otp_secret = pyotp.random_base32()
            user.save()

        otp_auth_url = f'otpauth://totp/PasswordManager:{user.username}?secret={user.otp_secret}&issuer=PasswordManager'
        qr = qrcode.make(otp_auth_url)
        buffer = io.BytesIO()
        qr.save(buffer, format="PNG")
        qr_base64 = base64.b64encode(buffer.getvalue()).decode()

        return Response({"qr_code": qr_base64, "otp_secret": user.otp_secret})



# Decrypts the password
class DecryptPasswordView(APIView):
    
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(request_body=IDSerializer)
    def post(self, request):
        serializer = IDSerializer(data=request.data)
        if serializer.is_valid():
            entry_id = serializer.validated_data["id"]
            password_entry = get_object_or_404(PasswordEntry, id=entry_id, user=request.user)

            decrypted_password = password_entry.decrypt_password()
            return Response({"decrypted_password": decrypted_password})
        else:
            return Response(serializer.errors, status=400)



class GeneratePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        length = request.GET.get('length', 12)

        try:
            length = int(length)
        except ValueError:
            return Response({"error": "Length must be a number."}, status=400)

        if length < 8 or length > 64:
            return Response({"error": "Length must be between 8 and 64."}, status=400)

        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for _ in range(length))

        return Response({"generated_password": password})



# Password change
class ChangePasswordView(APIView):
    
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(request_body=ChangePasswordSerializer)

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=400)

        user = request.user
        old_password = serializer.validated_data["old_password"]
        new_password = serializer.validated_data["new_password"]

        # Checking the old password
        if not check_password(old_password, user.password):
            return Response({"error": "The old password is incorrect"}, status=400)

        # Password change
        user.password = make_password(new_password)
        user.save()

        return Response({"message": "The password has been successfully changed"})




# Authorization with 2FA: login and password
class CustomLoginView(APIView):
    
    @swagger_auto_schema(request_body=LoginSerializer)
    
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        user = UserProfile.objects.filter(username=username).first()

        if not user:
            return Response({"error": "Invalid username or password"}, status=401)

        if user.is_locked():
            return Response({"error": "Too many attempts. Repeat after 10 minutes"}, status=403)

        if not authenticate(username=username, password=password):
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= 5:
                user.locked_until = now() + timedelta(minutes=10)
                user.failed_login_attempts = 5
            user.save()
            return Response({"error": "Invalid username or password"}, status=401)

        user.failed_login_attempts = 0
        user.locked_until = None
        user.save()

        if user.is_2fa_enabled:
            cache.set(f"otp_ready_{username}", True, timeout=180)  # Keep the flag for 3 minutes
            return Response({
                "2fa_required": True,
                "username": username
            }, status=200)

        # We mark that the user is logged in (without a token)
        cache.set(f"auth_ready_{username}", True, timeout=180)  # save the flag for 3 minutes
        return Response({"master_password_required": True, "username": username}, status=200)




#OTP code verification and access token issuance
class VerifyOTPView(APIView):

    @swagger_auto_schema(request_body=VerifyOTPSerializer)
    def post(self, request):
        username = request.data.get("username")
        otp_code = request.data.get("otp")

        if not username or not otp_code:
            return Response({"error": "We need both username and OTP code"}, status=400)

        user = UserProfile.objects.filter(username=username).first()
        if not user:
            return Response({"error": "The user was not found"}, status=404)

        if not user.is_2fa_enabled or not user.otp_secret:
            return Response({"error": "2FA is not enabled"}, status=400)

        if user.otp_locked_until and user.otp_locked_until > now():
            return Response({"error": "Too many attempts. Repeat later"}, status=403)

        if not cache.get(f"otp_ready_{username}"):
            return Response({"error": "It is impossible to enter an OTP without a login"}, status=403)

        if user.verify_otp(otp_code):
            # After successful OTP verification, we save the "ready to enter the master password" flag.
            cache.delete(f"otp_ready_{username}")
            cache.set(f"auth_ready_{username}", True, timeout=180)
            return Response({
                "master_password_required": True,
                "username": username
            }, status=200)

        return Response({"error": "Invalid OTP"}, status=400)



# Creates a digital HMAC signature based on a dictionary and secret
def sign_data(data, secret):
    message = json.dumps(data, sort_keys=True).encode()
    signature = hmac.new(secret, message, hashlib.sha256).hexdigest()
    return signature

# Checks whether the transmitted signature matches the expected one.
def verify_signature(data, signature, secret):
    expected = sign_data(data, secret)
    return hmac.compare_digest(signature, expected)



class ExportPasswordsView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        master_password = getattr(fernet_key, "current_password", None)
        if not master_password:
            return Response({"error": "Master password not available. Please log in and load it first."}, status=400)

        try:
            current = (
                fernet_key.current_fernet._fernets[0]
                if isinstance(fernet_key.current_fernet, MultiFernet)
                else fernet_key.current_fernet
            )
            fernet_key.current_fernet = load_all_fernet_keys(master_password, current_key=current)
        except Exception as e:
            print("[export] Could not load all fernet keys before export:", str(e))
            return Response({"error": "Could not load Fernet keys for export"}, status=400)

        if not fernet_key.current_fernet:
            return Response({"error": "Fernet key is not loaded"}, status=400)

        key_objects = (
            fernet_key.current_fernet._fernets
            if isinstance(fernet_key.current_fernet, MultiFernet)
            else [fernet_key.current_fernet]
        )

        print(f"[export] The number of keys before removing duplicates: {len(key_objects)}")

        # Removing duplicates on a base64 string
        seen_keys = set()
        unique_keys = []
        for f in key_objects:
            raw_key = f._signing_key + f._encryption_key
            b64_key = base64.urlsafe_b64encode(raw_key).decode()
            if b64_key not in seen_keys:
                seen_keys.add(b64_key)
                unique_keys.append((f, b64_key))


        print(f"[export] The number of keys after removing duplicates: {len(unique_keys)}")

        salt = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        derived_key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        export_fernet = Fernet(derived_key)

        encrypted_keys = []
        encoded_keys = []

        for i, (f, b64_key) in enumerate(unique_keys):
            encrypted = export_fernet.encrypt(b64_key.encode()).decode()
            encrypted_keys.append(encrypted)
            encoded_keys.append(b64_key)
            print(f"[key {i+1}] {b64_key}")

        try:
            save_additional_fernet_keys(master_password, encoded_keys)
        except Exception as e:
            print(f"[export] Could not update .keys.enc: {e}")

        entries = [
            {
                "website": p.website,
                "username": p.username,
                "password": p.password
            }
            for p in PasswordEntry.objects.filter(user=request.user)
        ]

        unsigned_data = {
            "salt": base64.b64encode(salt).decode(),
            "fernet_keys": encrypted_keys,
            "data": entries
        }

        signature = sign_data(unsigned_data, derived_key)
        export_content = {**unsigned_data, "signature": signature}

        response = JsonResponse(export_content, safe=False)
        response["Content-Disposition"] = 'attachment; filename="passwords_secure.json"'
        return response





class ImportPasswordsView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        uploaded_file = request.FILES.get("file")
        master_password = request.data.get("master_password")

        if not uploaded_file:
            return Response({"error": "The file has not been uploaded"}, status=400)
        if not master_password:
            return Response({"error": "Enter the master password"}, status=400)

        try:
            content = json.loads(uploaded_file.read().decode("utf-8"))
            salt = base64.b64decode(content["salt"])
            encrypted_keys = content["fernet_keys"]
            data = content["data"]
            signature = content["signature"]

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend(),
            )
            derived_key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
            import_fernet = Fernet(derived_key)

            unsigned_data = {
                "salt": content["salt"],
                "fernet_keys": encrypted_keys,
                "data": data
            }

            if not verify_signature(unsigned_data, signature, derived_key):
                return Response({"error": "Signature is invalid or file is corrupted"}, status=400)

            # Decryption of all keys
            all_keys = []
            raw_keys = []

            uploaded_file.seek(0)

            for i, enc_key in enumerate(encrypted_keys):
                try:
                    decrypted = import_fernet.decrypt(enc_key.encode())
                    all_keys.append(Fernet(decrypted))
                    raw_keys.append(decrypted.decode())
                    print(f"[ok] key {i} decrypted")
                except Exception as e:
                    print(f"[fail] key {i} - could not decrypt or decode base64: {str(e)}")

            # Adding the current keys
            if fernet_key.current_fernet:
                existing = (
                    fernet_key.current_fernet._fernets
                    if isinstance(fernet_key.current_fernet, MultiFernet)
                    else [fernet_key.current_fernet]
                )
                for f in existing:
                    key_b64 = base64.urlsafe_b64encode(f._signing_key + f._encryption_key).decode()
                    all_keys.append(f)
                    raw_keys.append(key_b64)

            if not all_keys:
                return Response({"error": "No valid Fernet keys could be decrypted"}, status=400)

            # using the current password saved after authorization.
            current_password = getattr(fernet_key, "current_password", None)
            if not current_password:
                return Response({"error": "Current master password is not available in memory"}, status=400)

            unique_keys = list(set(raw_keys))
            save_additional_fernet_keys(current_password, unique_keys)
            fernet_key.current_fernet = MultiFernet([Fernet(k.encode()) for k in unique_keys])

            # Decryption of records
            success_count = 0
            for i, entry in enumerate(data):
                try:
                    decrypted_password = fernet_key.current_fernet.decrypt(entry["password"].encode()).decode()
                    PasswordEntry.objects.create(
                        user=request.user,
                        website=entry["website"],
                        username=entry["username"],
                        password=decrypted_password,
                    )
                    success_count += 1
                except Exception as e:
                    print(f"[fail] entry {i} - failed to decrypt or save: {str(e)}")

            return Response({"message": f"{success_count} passwords have been successfully imported"})

        except Exception as e:
            import traceback
            print(traceback.format_exc())
            return Response({"error": f"Decryption error: {str(e)}"}, status=400)




def save_additional_fernet_keys(master_password: str, keys: list[str], file_path=".keys.enc"):
    # Clear the lines and delete the empty ones
    cleaned_keys = [k.strip() for k in keys if k.strip()]

    # Let's remove the duplicates, keeping the order
    seen = set()
    unique_keys = []
    for k in cleaned_keys:
        if k not in seen:
            seen.add(k)
            unique_keys.append(k)

    old_salt = None
    if os.path.exists(file_path):
        try:
            with open(file_path, "rb") as f:
                content = f.read()
                old_salt = content[:16]
                print("[save] Existing salt loaded")
        except Exception as e:
            print(f"[save] Failed to read old .keys.enc: {e}")

    salt = old_salt if old_salt else os.urandom(16)
    json_data = json.dumps(unique_keys).encode()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    derived_key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    fernet = Fernet(derived_key)
    encrypted = fernet.encrypt(json_data)

    with open(file_path, "wb") as f:
        f.write(salt + encrypted)

    print(f"[save] Saved {len(unique_keys)} unique keys to .keys.enc")
