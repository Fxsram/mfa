from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.shortcuts import redirect, render, get_object_or_404
from django.views.decorators.http import require_http_methods, require_GET, require_POST
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse, HttpResponseBadRequest
from django.conf import settings

import pyotp
import base64
import json
import os

from .forms import RegisterForm, LoginForm, OTPSetupForm, OTPVerifyForm
from .models import UserMFA, OTPType
from .utils import qr_png_base64

# WebAuthn config — set via environment variables in your deployment
RP_ID = os.environ.get("WEBAUTHN_RP_ID", "example.com")       # e.g. "example.com"
RP_NAME = os.environ.get("WEBAUTHN_RP_NAME", "MFA Demo")
ORIGIN = os.environ.get("WEBAUTHN_ORIGIN", "https://example.com")  # e.g. "https://example.com"

# NOTE: The server-side verification functions below use a Python WebAuthn library.
# Install one (e.g., `pip install webauthn` or `pip install fido2`) and adapt imports/verify calls as needed.
# The code below follows the common high level flow: generate options -> keep challenge in session -> verify response.

def _get_or_create_mfa(user):
    mfa, _ = UserMFA.objects.get_or_create(user=user)
    mfa.ensure_secret()
    return mfa

@require_http_methods(["GET", "POST"])
def register_view(request):
    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = User.objects.create_user(
                username=form.cleaned_data["username"],
                password=form.cleaned_data["password"],
            )
            _get_or_create_mfa(user)  # pre-create MFA row
            messages.success(request, "Registered. Now log in.")
            return redirect("accounts:login")
    else:
        form = RegisterForm()
    return render(request, "register.html", {"form": form})

@require_http_methods(["GET", "POST"])
def login_view(request):
    if request.method == "POST":
        form = LoginForm(request.POST)
        if form.is_valid():
            user = form.cleaned_data["user_obj"]
            request.session["pending_uid"] = user.id

            mfa = _get_or_create_mfa(user)
            if mfa.otp_type in (OTPType.TOTP, OTPType.HOTP):
                return redirect("accounts:otp_verify")
            if mfa.otp_type == OTPType.WEBAUTHN:
                return redirect("accounts:webauthn_auth")
            login(request, user)
            return redirect("accounts:profile")
    else:
        form = LoginForm()
    return render(request, "login.html", {"form": form})

@require_http_methods(["GET", "POST"])
def otp_verify_view(request):
    pending_uid = request.session.get("pending_uid")
    if not pending_uid:
        return redirect("accounts:login")

    user = User.objects.filter(id=pending_uid).first()
    if not user:
        messages.error(request, "Session expired. Please log in again.")
        return redirect("accounts:login")

    mfa = _get_or_create_mfa(user)

    if request.method == "POST":
        form = OTPVerifyForm(request.POST)
        if form.is_valid():
            code = form.cleaned_data["code"].strip()
            valid = False

            if mfa.otp_type == OTPType.TOTP:
                valid = mfa.totp_obj().verify(code, valid_window=1)
            elif mfa.otp_type == OTPType.HOTP:
                hotp = mfa.hotp_obj()
                for offset in range(0, 6):
                    if hotp.verify(code, mfa.hotp_counter + offset):
                        mfa.hotp_counter = mfa.hotp_counter + offset + 1  # advance beyond the used one
                        mfa.save(update_fields=["hotp_counter"])
                        valid = True
                        break

            if valid:
                del request.session["pending_uid"]
                login(request, user)
                return redirect("accounts:profile")
            else:
                messages.error(request, "Invalid or expired code.")
    else:
        form = OTPVerifyForm()

    return render(request, "otp_verify.html", {"form": form, "mfa": mfa})

@login_required
def profile_view(request):
    mfa = _get_or_create_mfa(request.user)
    context = {"mfa": mfa}
    return render(request, "profile.html", context)

@login_required
@require_http_methods(["GET", "POST"])
def otp_setup_view(request):
    mfa = _get_or_create_mfa(request.user)

    if request.method == "POST":
        form = OTPSetupForm(request.POST)
        if form.is_valid():
            choice = form.cleaned_data["otp_type"]
            if choice == OTPType.NONE:
                mfa.otp_type = OTPType.NONE
                mfa.save(update_fields=["otp_type"])
                messages.success(request, "MFA disabled.")
                return redirect("accounts:profile")

            mfa.secret = ""
            mfa.otp_type = choice
            mfa.hotp_counter = 0
            mfa.ensure_secret()
            mfa.save()
            messages.success(request, f"{mfa.get_otp_type_display()} enabled. Scan the QR code below.")
            return redirect("accounts:otp_setup")
    else:
        form = OTPSetupForm(initial={"otp_type": mfa.otp_type})

    provisioning_uri = mfa.provisioning_uri() if mfa.otp_type != OTPType.NONE else ""
    qr_data_uri = qr_png_base64(provisioning_uri) if provisioning_uri else ""
    live_totp = mfa.totp_obj().now() if mfa.otp_type == OTPType.TOTP else None

    return render(
        request,
        "otp_setup.html",
        {
            "form": form,
            "mfa": mfa,
            "provisioning_uri": provisioning_uri,
            "qr_data_uri": qr_data_uri,
            "live_totp": live_totp,
        },
    )

@login_required
def logout_view(request):
    logout(request)
    return redirect("accounts:login")

# -------------------------
# WebAuthn endpoints
# -------------------------
# Note: these use a typical flow: server generates options -> client creates/get -> server verifies
# You must adapt verification to the WebAuthn library you install.

# Utility helpers
def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def b64decode(s: str) -> bytes:
    padding = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + padding)

@login_required
@require_GET
def webauthn_setup_page(request):
    return render(request, "webauthn_setup.html", {})

@login_required
@require_GET
def webauthn_register_begin(request):
    challenge = os.urandom(32)
    request.session["webauthn_reg_challenge"] = b64(challenge)

    user = request.user
    user_id_b64 = b64(str(user.id).encode("utf-8"))

    options = {
        "publicKey": {
            "challenge": request.session["webauthn_reg_challenge"],
            "rp": {"name": RP_NAME, "id": RP_ID},
            "user": {"id": user_id_b64, "name": user.username, "displayName": user.username},
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}],
            "timeout": 60000,
            "attestation": "direct",
        }
    }
    return JsonResponse(options)

@csrf_exempt
@login_required
@require_POST
def webauthn_register_complete(request):
    try:
        body = json.loads(request.body)
    except Exception:
        return HttpResponseBadRequest("Invalid JSON")

    challenge_b64 = request.session.get("webauthn_reg_challenge")
    if not challenge_b64:
        return HttpResponseBadRequest("No registration in progress")

    client_data = body.get("response", {}).get("clientDataJSON")
    att_obj = body.get("response", {}).get("attestationObject")
    cred_id = body.get("id")
    if not (client_data and att_obj and cred_id):
        return HttpResponseBadRequest("Missing attestation fields")

    cred = {
        "id": cred_id,
        "public_key": "",
        "sign_count": 0,
        "transports": body.get("transports", []),
        "name": body.get("name", "Authenticator"),
    }

    mfa = _get_or_create_mfa(request.user)
    mfa.add_webauthn_credential(cred)
    mfa.otp_type = OTPType.WEBAUTHN
    mfa.save(update_fields=["otp_type", "webauthn_credentials"])

    return JsonResponse({"ok": True})

@require_GET
def webauthn_auth_page(request):
    return render(request, "webauthn_auth.html", {})

@require_GET
def webauthn_auth_begin(request):
    pending_uid = request.session.get("pending_uid")
    if not pending_uid:
        return HttpResponseBadRequest("No pending login")

    user = get_object_or_404(User, id=pending_uid)
    mfa = _get_or_create_mfa(user)

    allow_credentials = []
    for c in (mfa.webauthn_credentials or []):
        allow_credentials.append({"type": "public-key", "id": c.get("id")})

    challenge = os.urandom(32)
    request.session["webauthn_auth_challenge"] = b64(challenge)

    options = {
        "publicKey": {
            "challenge": request.session["webauthn_auth_challenge"],
            "timeout": 60000,
            "rpId": RP_ID,
            "allowCredentials": allow_credentials,
            "userVerification": "preferred",
        }
    }
    return JsonResponse(options)

@csrf_exempt
@require_POST
def webauthn_auth_complete(request):
    try:
        body = json.loads(request.body)
    except Exception:
        return HttpResponseBadRequest("Invalid JSON")

    challenge_b64 = request.session.get("webauthn_auth_challenge")
    if not challenge_b64:
        return HttpResponseBadRequest("No auth in progress")

    pending_uid = request.session.get("pending_uid")
    if not pending_uid:
        return HttpResponseBadRequest("No pending login")

    user = get_object_or_404(User, id=pending_uid)
    mfa = _get_or_create_mfa(user)

    cred_id = body.get("id")
    stored_cred = mfa.find_webauthn_credential(cred_id)
    if not stored_cred:
        return HttpResponseBadRequest("Unknown credential")

    stored_cred["sign_count"] = stored_cred.get("sign_count", 0) + 1
    mfa.save(update_fields=["webauthn_credentials"])

    request.session.pop("pending_uid", None)
    login(request, user)
    return JsonResponse({"ok": True})
