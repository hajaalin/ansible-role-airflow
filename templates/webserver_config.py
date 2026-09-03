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

            if email:
                user = self.find_user(email=email)
                if user:
                    return user

            return super().auth_user_oauth(userinfo)

    SECURITY_MANAGER_CLASS = CustomSecurityManager
else:
    AUTH_TYPE = AUTH_DB
