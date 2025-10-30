"""
accounts/views.py

Implements WebAuthn registration and authentication using the duo-labs/webauthn
library. This file replaces the placeholder verification code with real calls to
verify attestation and assertion and persists credential public key and signCount.

Requirements:
    pip install webauthn
Environment variables (set in deployment):
    WEBAUTHN_RP_ID    (e.g. example.com)
    WEBAUTHN_ORIGIN   (e.g. https://example.com)
    WEBAUTHN_RP_NAME  (optional friendly name)
"""
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

from webauthn import (
    generate_registration_options,
    options_to_json,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
)
from webauthn.helpers import bytes_to_base64url, base64url_to_bytes

from .forms import RegisterForm, LoginForm, OTPSetupForm, OTPVerifyForm
from .models import UserMFA, OTPType
from .utils import qr_png_base64

# WebAuthn config — set via environment variables in your deployment
RP_ID = os.environ.get("WEBAUTHN_RP_ID", "example.com")       # e.g. "example.com"
RP_NAME = os.environ.get("WEBAUTHN_RP_NAME", "MFA Demo")
ORIGIN = os.environ.get("WEBAUTHN_ORIGIN", "https://example.com")  # e.g. "https://example.com"

# Helper conversions
def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def b64decode(s: str) -> bytes:
    padding = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + padding)

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
    """Step 1: username+password. If user has MFA enabled, redirect to appropriate verify step."""
    if request.method == "POST":
        form = LoginForm(request.POST)
        if form.is_valid():
            user = form.cleaned_data["user_obj"]
            # store pending user id in session until factor verifies
            request.session["pending_uid"] = user.id

            mfa = _get_or_create_mfa(user)
            if mfa.otp_type in (OTPType.TOTP, OTPType.HOTP):
                return redirect("accounts:otp_verify")
            if mfa.otp_type == OTPType.WEBAUTHN:
                return redirect("accounts:webauthn_auth")
            # else straight login (MFA disabled)
            login(request, user)
            return redirect("accounts:profile")
    else:
        form = LoginForm()
    return render(request, "login.html", {"form": form})

@require_http_methods(["GET", "POST"])
def otp_verify_view(request):
    """Step 2: verify TOTP or HOTP depending on user's MFA setting."""
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
                # Allow a small window for clock drift (±1 step)
                valid = mfa.totp_obj().verify(code, valid_window=1)
            elif mfa.otp_type == OTPType.HOTP:
                # HOTP must advance on success. We allow checking a small look-ahead window to resync.
                hotp = mfa.hotp_obj()
                # try from current counter up to +5 (small window)
                for offset in range(0, 6):
                    if hotp.verify(code, mfa.hotp_counter + offset):
                        mfa.hotp_counter = mfa.hotp_counter + offset + 1  # advance beyond the used one
                        mfa.save(update_fields=["hotp_counter"])
                        valid = True
                        break

            if valid:
                # OTP ok → finalize login
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

            # Enable chosen factor and refresh secret to force re-enrollment
            mfa.secret = ""  # regenerate secret for new enrollment
            mfa.otp_type = choice
            mfa.hotp_counter = 0
            mfa.ensure_secret()
            mfa.save()
            messages.success(request, f"{mfa.get_otp_type_display()} enabled. Scan the QR code below.")
            return redirect("accounts:otp_setup")
    else:
        form = OTPSetupForm(initial={"otp_type": mfa.otp_type})

    # Show QR if a factor is enabled
    provisioning_uri = mfa.provisioning_uri() if mfa.otp_type != OTPType.NONE else ""
    qr_data_uri = qr_png_base64(provisioning_uri) if provisioning_uri else ""

    # For convenience, also show the current live code for TOTP users (useful for testing)
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
# WebAuthn endpoints (using duo-labs/webauthn)
# -------------------------

@login_required
@require_GET
def webauthn_setup_page(request):
    # Simple page to register an authenticator
    return render(request, "webauthn_setup.html", {})

@login_required
@require_GET
def webauthn_register_begin(request):
    """
    Generate PublicKeyCredentialCreationOptions for navigator.credentials.create()
    Uses duo-labs/webauthn helper generate_registration_options and options_to_json.
    Stores the raw challenge in session (base64url).
    """
    user = request.user
    # generate options
    options = generate_registration_options(
        rp_name=RP_NAME,
        rp_id=RP_ID,
        user_id=str(user.id),
        user_name=user.username,
        attestation="direct",
        pub_key_cred_params=[{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}],
    )
    # options.challenge is bytes; store base64url in session
    request.session["webauthn_reg_challenge"] = bytes_to_base64url(options.challenge)
    # Return JSON-friendly options for the browser
    return JsonResponse(json.loads(options_to_json(options)))

@csrf_exempt
@login_required
@require_POST
def webauthn_register_complete(request):
    """
    Verify attestation and persist the credential public key and sign count.
    Expects client JSON:
      {
        id, rawId, type,
        response: { clientDataJSON (b64), attestationObject (b64) },
        name: <optional display name>
      }
    """
    try:
        body = json.loads(request.body)
    except Exception:
        return HttpResponseBadRequest("Invalid JSON")

    expected_challenge_b64 = request.session.get("webauthn_reg_challenge")
    if not expected_challenge_b64:
        return HttpResponseBadRequest("No registration in progress")

    # duo-labs verify_registration_response expects the response object and several expected values
    try:
        verification = verify_registration_response(
            credential=body,
            expected_challenge=base64.urlsafe_b64decode(expected_challenge_b64 + "=="),
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            require_user_verification=True,
        )
    except Exception as exc:
        return JsonResponse({"ok": False, "error": str(exc)}, status=400)

    # verification contains credential_id (base64url), credential_public_key (COSE/bytes), sign_count (int)
    cred_id_b64 = verification.credential_id
    public_key_bytes = verification.credential_public_key
    sign_count = verification.sign_count

    # store public key as base64 (urlsafe) for persistence
    public_key_b64 = base64.urlsafe_b64encode(public_key_bytes).rstrip(b"=").decode("ascii")

    cred = {
        "id": cred_id_b64,
        "public_key": public_key_b64,
        "sign_count": sign_count,
        "transports": body.get("transports", []),
        "name": body.get("name", "Authenticator"),
    }

    mfa = _get_or_create_mfa(request.user)
    mfa.add_webauthn_credential(cred)
    mfa.otp_type = OTPType.WEBAUTHN
    mfa.save(update_fields=["otp_type", "webauthn_credentials"])

    # Clear registration challenge
    request.session.pop("webauthn_reg_challenge", None)
    return JsonResponse({"ok": True})

@require_GET
def webauthn_auth_page(request):
    # Page that runs the assertion flow (client will call /webauthn/auth/begin then navigator.credentials.get)
    return render(request, "webauthn_auth.html", {})

@require_GET
def webauthn_auth_begin(request):
    pending_uid = request.session.get("pending_uid")
    if not pending_uid:
        return HttpResponseBadRequest("No pending login")

    user = get_object_or_404(User, id=pending_uid)
    mfa = _get_or_create_mfa(user)

    # Build allowCredentials list: the library expects raw id bytes in the browser, we return base64url ids
    allow_credentials = []
    for c in (mfa.webauthn_credentials or []):
        # credential id is stored base64url
        allow_credentials.append({"type": "public-key", "id": c.get("id")})

    options = generate_authentication_options(rp_id=RP_ID, allow_credentials=allow_credentials, user_verification="preferred")
    # store challenge
    request.session["webauthn_auth_challenge"] = bytes_to_base64url(options.challenge)
    return JsonResponse(json.loads(options_to_json(options)))

@csrf_exempt
@require_POST
def webauthn_auth_complete(request):
    """
    Verify assertion and finalize login.
    Expects client JSON:
      {
        id, rawId, type,
        response: { authenticatorData, clientDataJSON, signature, userHandle }
      }
    """
    try:
        body = json.loads(request.body)
    except Exception:
        return HttpResponseBadRequest("Invalid JSON")

    expected_challenge_b64 = request.session.get("webauthn_auth_challenge")
    if not expected_challenge_b64:
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

    # Prepare verification inputs
    # credential_public_key was stored as base64; decode it back to bytes
    public_key_b64 = stored_cred.get("public_key", "")
    if not public_key_b64:
        return HttpResponseBadRequest("Stored credential missing public key")

    public_key_bytes = base64.urlsafe_b64decode(public_key_b64 + "==")

    try:
        verification = verify_authentication_response(
            credential=body,
            expected_challenge=base64.urlsafe_b64decode(expected_challenge_b64 + "=="),
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=public_key_bytes,
            credential_current_sign_count=stored_cred.get("sign_count", 0),
            require_user_verification=True,
        )
    except Exception as exc:
        return JsonResponse({"ok": False, "error": str(exc)}, status=400)

    # verification.new_sign_count is the updated counter — persist it
    new_sign_count = verification.new_sign_count
    # Update the stored credential sign_count in-place
    for c in (mfa.webauthn_credentials or []):
        if c.get("id") == cred_id:
            c["sign_count"] = new_sign_count
            break
    mfa.save(update_fields=["webauthn_credentials"])

    # Finalize login
    request.session.pop("webauthn_auth_challenge", None)
    request.session.pop("pending_uid", None)
    login(request, user)
    return JsonResponse({"ok": True})