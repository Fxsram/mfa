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
from django.core import signing
from django.core.cache import cache
from django.shortcuts import redirect, render, get_object_or_404
from django.urls import reverse
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.utils.encoding import force_str
from django.views.decorators.http import require_http_methods, require_GET, require_POST, require_safe
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie
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
from webauthn.helpers.structs import AttestationConveyancePreference
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import PublicKeyCredentialDescriptor, UserVerificationRequirement, \
    AttestationConveyancePreference

from .forms import RegisterForm, LoginForm, OTPSetupForm, OTPVerifyForm
from .models import UserMFA, OTPType
from .utils import qr_png_base64

# WebAuthn config — set via environment variables in your deployment
# RP_ID = os.environ.get("WEBAUTHN_RP_ID", "localhost")       # e.g. "example.com"
# RP_NAME = os.environ.get("WEBAUTHN_RP_NAME", "MFA Demo")
# ORIGIN = os.environ.get("WEBAUTHN_ORIGIN", "http://localhost:8000")  # e.g. "https://example.com"

RP_ID = os.environ.get("WEBAUTHN_RP_ID", "mfa.pythonanywhere.com")       # e.g. "example.com"
RP_NAME = os.environ.get("WEBAUTHN_RP_NAME", "MFA Demo")
ORIGIN = os.environ.get("WEBAUTHN_ORIGIN", "https://mfa.pythonanywhere.com")
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

    # NEW: WebAuthn QR to open the built-in setup page on another device
    webauthn_qr_data_uri = ""
    webauthn_handoff_url = ""
    if mfa.otp_type == OTPType.WEBAUTHN:
        payload = {"uid": request.user.id, "nonce": get_random_string(16), "ts": int(timezone.now().timestamp())}
        token = signing.dumps(payload, salt="webauthn-handoff")
        cache.set(f"webauthn:handoff:{token}:unused", True, timeout=300)  # 5 min
        handoff_path = reverse("accounts:webauthn_handoff_landing", args=[token])
        webauthn_handoff_url = f"{ORIGIN}{handoff_path}"
        webauthn_qr_data_uri = qr_png_base64(webauthn_handoff_url)

    return render(
        request,
        "otp_setup.html",
        {
            "form": form,
            "mfa": mfa,
            "provisioning_uri": provisioning_uri,
            "qr_data_uri": qr_data_uri,
            "live_totp": live_totp,
            # new:
            "webauthn_qr_data_uri": webauthn_qr_data_uri,
            "webauthn_handoff_url": webauthn_handoff_url,
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

# webauthn_register_begin (replace your current body)
@login_required
@require_GET
def webauthn_register_begin(request):
    user = request.user
    options = generate_registration_options(
        rp_name=RP_NAME,
        rp_id=RP_ID,
        user_name=user.username,
        user_id=str(user.id).encode("utf-8"),
        attestation=AttestationConveyancePreference.DIRECT,
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,          # -7
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,  # -257
        ],
    )
    request.session["webauthn_reg_challenge"] = bytes_to_base64url(options.challenge)
    return JsonResponse(json.loads(options_to_json(options)))

@csrf_exempt
@require_POST
def webauthn_register_complete(request):
    # 1) Parse
    try:
        body = json.loads(request.body.decode("utf-8"))
    except Exception:
        return JsonResponse({"ok": False, "stage": "parse", "error": "Invalid JSON"}, status=400)

    expected_challenge_b64 = request.session.get("webauthn_reg_challenge")
    if not expected_challenge_b64:
        return JsonResponse({"ok": False, "stage": "challenge", "error": "No registration in progress"}, status=400)

    # 2) Pick target user (mobile handoff or logged-in)
    target_uid = request.session.get("webauthn_enroll_uid") or (request.user.id if request.user.is_authenticated else None)
    if not target_uid:
        return JsonResponse({"ok": False, "stage": "user", "error": "No enrollment user in session"}, status=400)
    user = get_object_or_404(User, id=target_uid)
    mfa = _get_or_create_mfa(user)

    # 3) Verify attestation
    try:
        verification = verify_registration_response(
            credential=body,
            expected_challenge=base64url_to_bytes(expected_challenge_b64),
            expected_origin=ORIGIN,     # e.g. https://mfa.pythonanywhere.com  (NO trailing slash)
            expected_rp_id=RP_ID,       # e.g. mfa.pythonanywhere.com
            require_user_verification=False,   # or True if you want strict UV
        )
    except Exception as exc:
        return JsonResponse({"ok": False, "stage": "verify", "error": str(exc)}, status=400)

    # 4) Normalize everything to JSON-safe strings
    # credential_id may be bytes or str depending on library/version
    cred_id_bytes = verification.credential_id
    if isinstance(cred_id_bytes, str):
        cred_id_b64 = cred_id_bytes  # already base64url in some builds
    else:
        cred_id_b64 = bytes_to_base64url(cred_id_bytes)

    pubkey_bytes = verification.credential_public_key  # bytes
    public_key_b64 = base64.urlsafe_b64encode(pubkey_bytes).rstrip(b"=").decode("ascii")

    sign_count = int(verification.sign_count or 0)

    cred = {
        "id": cred_id_b64,                 # base64url string
        "public_key": public_key_b64,      # base64url string
        "sign_count": sign_count,          # int
        "transports": body.get("transports", []),
        "name": body.get("name", "Authenticator"),
    }

    # 5) Persist to JSONField (bytes-free)
    mfa.add_webauthn_credential(cred)
    mfa.otp_type = OTPType.WEBAUTHN
    mfa.save(update_fields=["otp_type", "webauthn_credentials"])

    # 6) Cleanup session markers
    request.session.pop("webauthn_reg_challenge", None)
    request.session.pop("webauthn_enroll_uid", None)
    request.session.pop("webauthn_enroll_at", None)

    return JsonResponse({"ok": True})

@require_GET
def webauthn_auth_page(request):
    # Page that runs the assertion flow (client will call /webauthn/auth/begin then navigator.credentials.get)
    return render(request, "webauthn_auth.html", {})

@require_GET
@require_GET
def webauthn_auth_begin(request):
    pending_uid = request.session.get("pending_uid")
    if not pending_uid:
        return HttpResponseBadRequest("No pending login")

    user = get_object_or_404(User, id=pending_uid)
    mfa = _get_or_create_mfa(user)

    # IDs must be raw bytes for the options object
    allow_credentials = []
    for c in (mfa.webauthn_credentials or []):
        cred_id_bytes = base64url_to_bytes(c.get("id"))
        allow_credentials.append(
            PublicKeyCredentialDescriptor(id=cred_id_bytes, type="public-key")
        )

    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.PREFERRED,  # enum, not "preferred"
    )
    request.session["webauthn_auth_challenge"] = bytes_to_base64url(options.challenge)
    return JsonResponse(json.loads(options_to_json(options)))

@csrf_exempt
@require_POST
def webauthn_auth_complete(request):
    try:
        body = json.loads(request.body)
    except Exception:
        return JsonResponse({"ok": False, "error": "Invalid JSON"}, status=400)

    expected_challenge_b64 = request.session.get("webauthn_auth_challenge")
    if not expected_challenge_b64:
        return JsonResponse({"ok": False, "error": "No auth in progress"}, status=400)

    pending_uid = request.session.get("pending_uid")
    if not pending_uid:
        return JsonResponse({"ok": False, "error": "No pending login"}, status=400)

    user = get_object_or_404(User, id=pending_uid)
    mfa = _get_or_create_mfa(user)

    # Prefer body.id, but also try rawId (some stacks compare these differently)
    incoming_id = body.get("id")
    incoming_raw_id_b64 = body.get("rawId")
    if not incoming_id and incoming_raw_id_b64:
        incoming_id = incoming_raw_id_b64  # both are b64url strings on the wire

    stored_cred = None
    for c in (mfa.webauthn_credentials or []):
        if c.get("id") == incoming_id:
            stored_cred = c
            break
        # also try matching against decoded rawId if needed
        if incoming_raw_id_b64:
            try:
                if c.get("id") == force_str(incoming_raw_id_b64):
                    stored_cred = c
                    break
            except Exception:
                pass

    if not stored_cred:
        return JsonResponse({"ok": False, "error": "Unknown credential"}, status=400)

    public_key_b64 = stored_cred.get("public_key", "")
    if not public_key_b64:
        return JsonResponse({"ok": False, "error": "Stored credential missing public key"}, status=400)
    public_key_bytes = base64.urlsafe_b64decode(public_key_b64 + "==")

    try:
        verification = verify_authentication_response(
            credential=body,
            expected_challenge=base64url_to_bytes(expected_challenge_b64),
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=public_key_bytes,
            credential_current_sign_count=stored_cred.get("sign_count", 0),
            require_user_verification=True,
        )
    except Exception as exc:
        return JsonResponse({"ok": False, "error": str(exc)}, status=400)

    # Persist counter
    new_sign_count = verification.new_sign_count
    for c in (mfa.webauthn_credentials or []):
        if c.get("id") == stored_cred.get("id"):
            c["sign_count"] = new_sign_count
            break
    mfa.save(update_fields=["webauthn_credentials"])

    # Finalize login
    request.session.pop("webauthn_auth_challenge", None)
    request.session.pop("pending_uid", None)
    login(request, user)
    return JsonResponse({"ok": True})




@require_safe
def webauthn_handoff_landing(request, token: str):
    # one-time token to bind this (phone) session to the desktop user
    if not cache.get(f"webauthn:handoff:{token}:unused"):
        return HttpResponseBadRequest("This link is no longer valid.")
    try:
        data = signing.loads(token, salt="webauthn-handoff", max_age=300)
    except signing.BadSignature:
        return HttpResponseBadRequest("Invalid or expired link.")
    cache.delete(f"webauthn:handoff:{token}:unused")
    request.session["webauthn_enroll_uid"] = int(data["uid"])
    request.session["webauthn_enroll_at"] = timezone.now().isoformat()
    return redirect("accounts:webauthn_setup_mobile_page")

@require_GET
def webauthn_register_begin_mobile(request):
    uid = request.session.get("webauthn_enroll_uid")
    if not uid:
        return HttpResponseBadRequest("No enrollment session.")
    user = get_object_or_404(User, id=uid)
    options = generate_registration_options(
        rp_name=RP_NAME,
        rp_id=RP_ID,
        user_name=user.username,
        user_id=str(user.id).encode("utf-8"),
        attestation=AttestationConveyancePreference.DIRECT,
        supported_pub_key_algs=[-7, -257],  # ECDSA_SHA_256, RSASSA_PKCS1_v1_5_SHA_256
    )
    request.session["webauthn_reg_challenge"] = bytes_to_base64url(options.challenge)
    return JsonResponse(json.loads(options_to_json(options)))

@ensure_csrf_cookie
@require_GET
def webauthn_setup_mobile_page(request):
    """Render the mobile registration page (for when user scanned the QR)."""
    return render(request, "webauthn_setup_mobile.html")