from django.urls import path
from . import views

app_name = "accounts"

urlpatterns = [
    path("register/", views.register_view, name="register"),
    path("login/", views.login_view, name="login"),         # Step 1: username+password
    path("otp/verify/", views.otp_verify_view, name="otp_verify"),  # Step 2: OTP code
    path("otp/setup/", views.otp_setup_view, name="otp_setup"),     # Choose TOTP/HOTP
    path("profile/", views.profile_view, name="profile"),
    path("logout/", views.logout_view, name="logout"),

    # WebAuthn endpoints & pages
    path("webauthn/setup/", views.webauthn_setup_page, name="webauthn_setup"),
    path("webauthn/register/begin/", views.webauthn_register_begin, name="webauthn_register_begin"),
    path("webauthn/register/complete/", views.webauthn_register_complete, name="webauthn_register_complete"),
    path("webauthn/auth/", views.webauthn_auth_page, name="webauthn_auth"),
    path("webauthn/auth/begin/", views.webauthn_auth_begin, name="webauthn_auth_begin"),
    path("webauthn/auth/complete/", views.webauthn_auth_complete, name="webauthn_auth_complete"),

    path("webauthn/handoff/<str:token>/", views.webauthn_handoff_landing, name="webauthn_handoff_landing"),
    path("webauthn/setup/mobile/", views.webauthn_setup_mobile_page, name="webauthn_setup_mobile_page"),
    path("webauthn/register/begin/mobile/", views.webauthn_register_begin_mobile,name="webauthn_register_begin_mobile"),

    path("nca/setup/", views.nca_setup_page, name="nca_setup"),
    path("nca/auth/", views.nca_auth_page, name="nca_auth"),
    path("api/cms/", views.cms_verify_and_login, name="cms_verify_and_login"),

]