import logging
import os
from flask_appbuilder.security.manager import AUTH_DB, AUTH_OAUTH
from airflow.providers.fab.auth_manager.security_manager.override import FabAirflowSecurityManagerOverride

log = logging.getLogger(__name__)

# ----------------------------------------------------
# Basic Security
# ----------------------------------------------------
CSRF_ENABLED = True

# ----------------------------------------------------
# Authentication
# ----------------------------------------------------
# Google OAuth is optional: only enable it when credentials are actually
# configured, otherwise fall back to FAB's normal DB-backed username/password
# auth (e.g. `airflow users create`) instead of hard-failing at import time.
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")

# Comma-separated list, e.g. "helsinki.fi". Empty means no restriction -
# any Google account can log in and self-register, which you almost
# certainly don't want on anything reachable outside your own network.
GOOGLE_ALLOWED_DOMAINS = [
    d.strip().lower()
    for d in os.environ.get("GOOGLE_ALLOWED_DOMAINS", "").split(",")
    if d.strip()
]

# Empty = no restriction. Non-empty restricts to these exact addresses, in
# ADDITION to GOOGLE_ALLOWED_DOMAINS above (both must pass if both are set).
GOOGLE_ALLOWED_EMAILS = [
    e.strip().lower()
    for e in os.environ.get("GOOGLE_ALLOWED_EMAILS", "").split(",")
    if e.strip()
]

if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    AUTH_TYPE = AUTH_OAUTH
    AUTH_USER_REGISTRATION = True
    AUTH_USER_REGISTRATION_ROLE = "Viewer"

    OAUTH_PROVIDERS = [
        {
            "name": "google",
            "icon": "fa-google",
            "token_key": "access_token",
            "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
            "remote_app": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "server_metadata_url": "https://accounts.google.com/.well-known/openid-configuration",
                "api_base_url": "https://openidconnect.googleapis.com/v1/",
                "client_kwargs": {
                    "scope": "openid email profile"
                },
            },
        }
    ]

    class CustomSecurityManager(FabAirflowSecurityManagerOverride):

        def get_oauth_user_info(self, provider, resp):
            # FAB's own get_oauth_user_info() hardcodes data.get("id", "")
            # for the "google" provider, which was correct for Google's old
            # OAuth2 v2 userinfo API but NOT for the OIDC-standard endpoint
            # this config actually points at (userinfo_endpoint above) -
            # that endpoint returns "sub", not "id", so the built-in FAB
            # logic silently builds username "google_" (empty suffix) for
            # EVERY Google user, colliding them all onto one account. Fix
            # it here rather than relying on FAB's provider-name special
            # casing, which predates OIDC-standard userinfo responses.
            if provider == "google":
                me = self.appbuilder.sm.oauth_remotes[provider].get("userinfo")
                data = me.json()
                return {
                    "username": "google_" + data.get("sub", ""),
                    "first_name": data.get("given_name", ""),
                    "last_name": data.get("family_name", ""),
                    "email": data.get("email", ""),
                }
            return super().get_oauth_user_info(provider, resp)

        def auth_user_oauth(self, userinfo):
            email = userinfo.get("email")

            if GOOGLE_ALLOWED_DOMAINS and email:
                domain = email.rsplit("@", 1)[-1].lower()
                if domain not in GOOGLE_ALLOWED_DOMAINS:
                    log.warning(
                        "Rejecting OAuth login for %s: domain %s not in %s",
                        email, domain, GOOGLE_ALLOWED_DOMAINS,
                    )
                    return None

            if GOOGLE_ALLOWED_EMAILS and email and email.lower() not in GOOGLE_ALLOWED_EMAILS:
                log.warning(
                    "Rejecting OAuth login for %s: not in GOOGLE_ALLOWED_EMAILS",
                    email,
                )
                return None

            if email:
                user = self.find_user(email=email)
                if user:
                    return user

            return super().auth_user_oauth(userinfo)

    SECURITY_MANAGER_CLASS = CustomSecurityManager
else:
    AUTH_TYPE = AUTH_DB
