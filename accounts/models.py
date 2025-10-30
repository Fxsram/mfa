from django.conf import settings
from django.db import models
import pyotp
import base64
import json

# Add a WebAuthn option
class OTPType(models.TextChoices):
    NONE = "NONE", "None"
    TOTP = "TOTP", "Time-based (TOTP)"
    HOTP = "HOTP", "Counter-based (HOTP)"
    WEBAUTHN = "WEBAUTHN", "Biometric / WebAuthn"

class UserMFA(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="mfa")

    # Shared secret used by pyotp (base32)
    secret = models.CharField(max_length=64, blank=True, default="")

    # Which OTP is enabled for this user
    otp_type = models.CharField(max_length=12, choices=OTPType.choices, default=OTPType.NONE)

    # HOTP counter (only used when otp_type == HOTP)
    hotp_counter = models.PositiveIntegerField(default=0)

    issuer = models.CharField(max_length=64, default="PyOTP-MFA-Demo")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # JSON field to store a list of WebAuthn credentials
    # Example structure:
    # [
    #   {
    #     "id": "<base64url>",
    #     "public_key": "<base64 or COSE key>",
    #     "sign_count": 0,
    #     "transports": ["usb", "ble"],
    #     "name": "My phone"
    #   }
    # ]
    try:
        # Django >= 3.1
        JSONField = models.JSONField
    except AttributeError:
        # Fallback for older versions using Postgres-specific field
        from django.contrib.postgres.fields import JSONField as JSONField  # type: ignore

    webauthn_credentials = JSONField(default=list, blank=True)

    def __str__(self):
        return f"MFA({self.user.username}) {self.otp_type}"

    # Helpers
    def ensure_secret(self):
        if not self.secret:
            self.secret = pyotp.random_base32() # 160-bit default
            self.save(update_fields=["secret"])

    def totp_obj(self, interval=30, digits=6):
        self.ensure_secret()
        return pyotp.TOTP(self.secret, interval=interval, digits=digits)

    def hotp_obj(self, digits=6):
        self.ensure_secret()
        return pyotp.HOTP(self.secret, digits=digits)

    def provisioning_uri(self):
        """
        Google Authenticator-compatible URI.
        Uses account name as user.username. Adjust to email if you prefer.
        """
        self.ensure_secret()
        if self.otp_type == OTPType.TOTP:
            return self.totp_obj().provisioning_uri(name=self.user.username, issuer_name=self.issuer)
        elif self.otp_type == OTPType.HOTP:
            return self.hotp_obj().provisioning_uri(name=self.user.username, issuer_name=self.issuer, initial_count=self.hotp_counter)
        return ""

    # WebAuthn credential helpers
    def add_webauthn_credential(self, cred_dict):
        creds = list(self.webauthn_credentials or [])
        creds.append(cred_dict)
        self.webauthn_credentials = creds
        self.save(update_fields=["webauthn_credentials"])

    def find_webauthn_credential(self, cred_id):
        for c in (self.webauthn_credentials or []):
            if c.get("id") == cred_id:
                return c
        return None
