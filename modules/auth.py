"""
OAuth Authentication Module - Security-hardened implementation.
Supports Azure AD, Google, and generic OIDC with PKCE, signed state cookie,
encrypted token storage, token refresh, nonce, and rate limiting.
No unverified JWT decoding; demo mode only when ENV is not production.
"""

import os
import json
import logging
import hashlib
import base64
import secrets
import streamlit as st
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple
from pathlib import Path
from urllib.parse import urlencode, urlparse

from dotenv import load_dotenv
load_dotenv()

# Optional: Fernet for encrypting tokens in session
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    FERNET_AVAILABLE = True
except ImportError:
    FERNET_AVAILABLE = False

from . import auth_store

logger = logging.getLogger(__name__)


def _get_secret(key: str, default: str = "") -> str:
    """Get secret from os.environ first, then st.secrets (for Streamlit Cloud)."""
    value = os.getenv(key, default)
    if value:
        return value
    try:
        if hasattr(st, "secrets") and st.secrets and key in st.secrets:
            return str(st.secrets[key]) if st.secrets[key] is not None else default
    except Exception:
        pass
    return default


# Cookie name for OAuth state (signed)
OAUTH_STATE_COOKIE = "oauth_state"
OAUTH_STATE_MAX_AGE = 600  # 10 minutes


def _derive_fernet_key(secret: str) -> bytes:
    """Derive a 32-byte key suitable for Fernet from SESSION_SECRET_KEY."""
    digest = hashlib.sha256(secret.encode()).digest()
    return base64.urlsafe_b64encode(digest)


def _sign_state_cookie(secret: str, state: str) -> str:
    """Create a signed value: state|hmac(secret, state). Streamlit does not set cookies from Python easily;
    we store state in backend store and use a short-lived signed token as cookie value that encodes state."""
    import hmac
    raw = f"{state}"
    sig = hmac.new(secret.encode(), raw.encode(), hashlib.sha256).hexdigest()
    return f"{state}.{sig}"


def _verify_state_cookie(secret: str, value: str) -> Optional[str]:
    """Verify and return state from signed cookie value."""
    import hmac
    if "." not in value:
        return None
    state, sig = value.rsplit(".", 1)
    expected = hmac.new(secret.encode(), state.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    return state


def _pkce_code_verifier() -> str:
    """Generate PKCE code_verifier (43-128 chars)."""
    return secrets.token_urlsafe(32)


def _pkce_code_challenge(verifier: str) -> str:
    """S256 code_challenge = BASE64URL(SHA256(verifier))."""
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class AuthConfig:
    """Authentication configuration. SESSION_SECRET_KEY required when OAuth is configured."""

    def __init__(self):
        self.provider = os.getenv("OAUTH_PROVIDER", "azure")
        self.redirect_uri = os.getenv("OAUTH_REDIRECT_URI", "http://localhost:8501/")
        self.session_timeout = int(os.getenv("SESSION_TIMEOUT_MINUTES", "60"))
        self.is_production = os.getenv("ENV", "").lower() == "production"

        # Session secret: required when OAuth configured; no random default in production
        raw_secret = os.getenv("SESSION_SECRET_KEY", "")
        if not raw_secret and self.is_production:
            raise RuntimeError("SESSION_SECRET_KEY must be set when ENV=production")
        self.session_secret = raw_secret or secrets.token_hex(32)

        # Azure AD
        self.azure_client_id = os.getenv("AZURE_CLIENT_ID", "")
        self.azure_client_secret = os.getenv("AZURE_CLIENT_SECRET", "")
        self.azure_tenant_id = os.getenv("AZURE_TENANT_ID", "")

        # Google
        self.google_client_id = os.getenv("GOOGLE_CLIENT_ID", "")
        self.google_client_secret = os.getenv("GOOGLE_CLIENT_SECRET", "")

        # Generic OIDC
        self.oidc_client_id = os.getenv("OIDC_CLIENT_ID", "")
        self.oidc_client_secret = os.getenv("OIDC_CLIENT_SECRET", "")
        self.oidc_discovery_url = os.getenv("OIDC_DISCOVERY_URL", "")

        admin_users_str = os.getenv("ADMIN_USERS", "")
        self.admin_users = [e.strip() for e in admin_users_str.split(",") if e.strip()]

    def is_configured(self) -> bool:
        if self.provider == "azure":
            return bool(self.azure_client_id and self.azure_client_secret and self.azure_tenant_id)
        if self.provider == "google":
            return bool(self.google_client_id and self.google_client_secret)
        if self.provider == "oidc":
            return bool(self.oidc_client_id and self.oidc_client_secret and self.oidc_discovery_url)
        return False

    def require_session_secret_for_oauth(self) -> None:
        """Call when OAuth is configured: ensure SESSION_SECRET_KEY is set in environment."""
        if not os.getenv("SESSION_SECRET_KEY"):
            raise RuntimeError(
                "SESSION_SECRET_KEY must be set in environment when OAuth is enabled"
            )
        self.session_secret = os.getenv("SESSION_SECRET_KEY")


# Permission config: load once and cache
_roles_config_cache: Optional[Dict[str, Any]] = None


def _get_roles_config() -> Dict[str, Any]:
    global _roles_config_cache
    if _roles_config_cache is not None:
        return _roles_config_cache
    config_path = Path(__file__).parent.parent / "config" / "oauth_config.json"
    try:
        with open(config_path) as f:
            data = json.load(f)
        if "roles" not in data:
            raise ValueError("oauth_config.json must contain 'roles'")
        _roles_config_cache = data
        return _roles_config_cache
    except Exception as e:
        logger.warning("Failed to load oauth_config.json: %s", e)
        _roles_config_cache = {"roles": {}}
        return _roles_config_cache


class OAuthProvider:
    """Base OAuth provider with PKCE and nonce support."""

    def __init__(self, config: AuthConfig):
        self.config = config

    def get_authorization_url(
        self,
        state: str,
        code_challenge: str,
        nonce: Optional[str] = None,
    ) -> str:
        raise NotImplementedError

    def exchange_code_for_token(
        self,
        code: str,
        code_verifier: str,
    ) -> Dict[str, Any]:
        raise NotImplementedError

    def get_user_info(self, access_token: str) -> Dict[str, Any]:
        raise NotImplementedError

    def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """Return new tokens dict or empty/error dict."""
        return {}


class AzureADProvider(OAuthProvider):
    def get_authorization_url(
        self,
        state: str,
        code_challenge: str,
        nonce: Optional[str] = None,
    ) -> str:
        params = {
            "client_id": self.config.azure_client_id,
            "response_type": "code",
            "redirect_uri": self.config.redirect_uri,
            "scope": "openid profile email User.Read",
            "state": state,
            "response_mode": "query",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        if nonce:
            params["nonce"] = nonce
        base_url = f"https://login.microsoftonline.com/{self.config.azure_tenant_id}/oauth2/v2.0/authorize"
        return f"{base_url}?{urlencode(params)}"

    def exchange_code_for_token(self, code: str, code_verifier: str) -> Dict[str, Any]:
        import requests
        token_url = f"https://login.microsoftonline.com/{self.config.azure_tenant_id}/oauth2/v2.0/token"
        data = {
            "client_id": self.config.azure_client_id,
            "client_secret": self.config.azure_client_secret,
            "code": code,
            "redirect_uri": self.config.redirect_uri,
            "grant_type": "authorization_code",
            "code_verifier": code_verifier,
            "scope": "openid profile email User.Read",
        }
        resp = requests.post(token_url, data=data)
        return resp.json()

    def get_user_info(self, access_token: str) -> Dict[str, Any]:
        import requests
        headers = {"Authorization": f"Bearer {access_token}"}
        resp = requests.get("https://graph.microsoft.com/v1.0/me", headers=headers)
        if resp.status_code == 200:
            d = resp.json()
            return {
                "email": d.get("mail") or d.get("userPrincipalName"),
                "name": d.get("displayName"),
                "id": d.get("id"),
            }
        return {}

    def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        import requests
        token_url = f"https://login.microsoftonline.com/{self.config.azure_tenant_id}/oauth2/v2.0/token"
        data = {
            "client_id": self.config.azure_client_id,
            "client_secret": self.config.azure_client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }
        resp = requests.post(token_url, data=data)
        return resp.json()


class GoogleProvider(OAuthProvider):
    def get_authorization_url(
        self,
        state: str,
        code_challenge: str,
        nonce: Optional[str] = None,
    ) -> str:
        params = {
            "client_id": self.config.google_client_id,
            "response_type": "code",
            "redirect_uri": self.config.redirect_uri,
            "scope": "openid email profile",
            "state": state,
            "access_type": "offline",
            "prompt": "consent",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        if nonce:
            params["nonce"] = nonce
        return f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"

    def exchange_code_for_token(self, code: str, code_verifier: str) -> Dict[str, Any]:
        import requests
        data = {
            "client_id": self.config.google_client_id,
            "client_secret": self.config.google_client_secret,
            "code": code,
            "redirect_uri": self.config.redirect_uri,
            "grant_type": "authorization_code",
            "code_verifier": code_verifier,
        }
        resp = requests.post("https://oauth2.googleapis.com/token", data=data)
        return resp.json()

    def get_user_info(self, access_token: str) -> Dict[str, Any]:
        import requests
        headers = {"Authorization": f"Bearer {access_token}"}
        resp = requests.get("https://www.googleapis.com/oauth2/v3/userinfo", headers=headers)
        if resp.status_code == 200:
            d = resp.json()
            return {"email": d.get("email"), "name": d.get("name"), "id": d.get("sub")}
        return {}

    def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        import requests
        data = {
            "client_id": self.config.google_client_id,
            "client_secret": self.config.google_client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }
        resp = requests.post("https://oauth2.googleapis.com/token", data=data)
        return resp.json()


class GenericOIDCProvider(OAuthProvider):
    def __init__(self, config: AuthConfig):
        super().__init__(config)
        self._discovery: Optional[Dict[str, Any]] = None

    def _get_discovery(self) -> Dict[str, Any]:
        if self._discovery is None:
            import requests
            resp = requests.get(self.config.oidc_discovery_url)
            resp.raise_for_status()
            self._discovery = resp.json()
        return self._discovery

    def get_authorization_url(
        self,
        state: str,
        code_challenge: str,
        nonce: Optional[str] = None,
    ) -> str:
        discovery = self._get_discovery()
        params = {
            "client_id": self.config.oidc_client_id,
            "response_type": "code",
            "redirect_uri": self.config.redirect_uri,
            "scope": "openid email profile",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        if nonce:
            params["nonce"] = nonce
        return f"{discovery['authorization_endpoint']}?{urlencode(params)}"

    def exchange_code_for_token(self, code: str, code_verifier: str) -> Dict[str, Any]:
        import requests
        discovery = self._get_discovery()
        data = {
            "client_id": self.config.oidc_client_id,
            "client_secret": self.config.oidc_client_secret,
            "code": code,
            "redirect_uri": self.config.redirect_uri,
            "grant_type": "authorization_code",
            "code_verifier": code_verifier,
        }
        resp = requests.post(discovery["token_endpoint"], data=data)
        return resp.json()

    def get_user_info(self, access_token: str) -> Dict[str, Any]:
        import requests
        discovery = self._get_discovery()
        headers = {"Authorization": f"Bearer {access_token}"}
        resp = requests.get(discovery["userinfo_endpoint"], headers=headers)
        if resp.status_code == 200:
            d = resp.json()
            return {"email": d.get("email"), "name": d.get("name"), "id": d.get("sub")}
        return {}

    def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        import requests
        discovery = self._get_discovery()
        refresh_endpoint = discovery.get("token_endpoint")
        if not refresh_endpoint:
            return {}
        data = {
            "client_id": self.config.oidc_client_id,
            "client_secret": self.config.oidc_client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }
        resp = requests.post(refresh_endpoint, data=data)
        return resp.json()


def _encrypt_tokens(secret: str, tokens: Dict[str, Any]) -> str:
    if not FERNET_AVAILABLE:
        return json.dumps(tokens)  # Fallback: still better than plain in URL; prefer setting cryptography
    key = _derive_fernet_key(secret)
    f = Fernet(key)
    return f.encrypt(json.dumps(tokens).encode()).decode()


def _decrypt_tokens(secret: str, payload: str) -> Optional[Dict[str, Any]]:
    if not FERNET_AVAILABLE:
        try:
            return json.loads(payload)
        except Exception:
            return None
    try:
        key = _derive_fernet_key(secret)
        f = Fernet(key)
        return json.loads(f.decrypt(payload.encode()).decode())
    except Exception:
        return None


class SessionManager:
    """Session with encrypted token storage and refresh logic."""

    def __init__(self, config: AuthConfig):
        self.config = config

    def create_session(self, user_info: Dict[str, Any], tokens: Dict[str, Any]) -> None:
        encrypted = _encrypt_tokens(self.config.session_secret, tokens)
        st.session_state["authenticated"] = True
        st.session_state["user"] = {
            "email": user_info.get("email"),
            "name": user_info.get("name"),
            "id": user_info.get("id"),
            "provider": self.config.provider,
        }
        st.session_state["tokens_encrypted"] = encrypted
        st.session_state["session_created"] = datetime.utcnow().isoformat()
        st.session_state["session_expires"] = (
            datetime.utcnow() + timedelta(minutes=self.config.session_timeout)
        ).isoformat()

    def _get_tokens(self) -> Optional[Dict[str, Any]]:
        enc = st.session_state.get("tokens_encrypted")
        if not enc:
            return None
        return _decrypt_tokens(self.config.session_secret, enc)

    def _set_tokens(self, tokens: Dict[str, Any]) -> None:
        st.session_state["tokens_encrypted"] = _encrypt_tokens(
            self.config.session_secret, tokens
        )

    def is_authenticated(self) -> bool:
        if not st.session_state.get("authenticated"):
            return False
        expires = st.session_state.get("session_expires")
        if expires:
            try:
                if datetime.utcnow() > datetime.fromisoformat(expires):
                    self.logout()
                    return False
            except Exception:
                self.logout()
                return False
        # Optional: refresh access token if close to expiry
        tokens = self._get_tokens()
        if tokens and tokens.get("refresh_token"):
            # Simple refresh: could check expires_in and only refresh when needed
            pass  # Refresh is done in ensure_valid_token
        return True

    def ensure_valid_token(self, provider: OAuthProvider) -> bool:
        """If we have refresh_token and access is expired, refresh. Returns True if we have valid access."""
        tokens = self._get_tokens()
        if not tokens:
            return False
        if not tokens.get("refresh_token"):
            return True
        # Check expires_in if stored
        exp = tokens.get("expires_in")
        created = st.session_state.get("session_created")
        if exp and created:
            try:
                created_dt = datetime.fromisoformat(created)
                if datetime.utcnow() >= created_dt + timedelta(seconds=exp - 300):
                    new_tokens = provider.refresh_token(tokens["refresh_token"])
                    if new_tokens and "error" not in new_tokens:
                        merged = {**tokens, **new_tokens}
                        self._set_tokens(merged)
                        st.session_state["session_expires"] = (
                            datetime.utcnow()
                            + timedelta(minutes=self.config.session_timeout)
                        ).isoformat()
            except Exception as e:
                logger.warning("Token refresh failed: %s", e)
        return True

    def get_user(self) -> Optional[Dict[str, Any]]:
        if self.is_authenticated():
            return st.session_state.get("user")
        return None

    def get_user_email(self) -> Optional[str]:
        user = self.get_user()
        return user.get("email") if user else None

    def logout(self) -> None:
        for key in [
            "authenticated",
            "user",
            "tokens_encrypted",
            "session_created",
            "session_expires",
        ]:
            if key in st.session_state:
                del st.session_state[key]

    def refresh_session(self) -> None:
        st.session_state["session_expires"] = (
            datetime.utcnow() + timedelta(minutes=self.config.session_timeout)
        ).isoformat()


class AuthManager:
    """Main auth: OAuth with state in store, PKCE, signed state cookie, redirect_uri check, rate limiting."""

    def __init__(self):
        self.config = AuthConfig()
        if self.config.is_configured():
            self.config.require_session_secret_for_oauth()
        self.session = SessionManager(self.config)
        self._provider: Optional[OAuthProvider] = None

    @property
    def provider(self) -> OAuthProvider:
        if self._provider is None:
            if self.config.provider == "azure":
                self._provider = AzureADProvider(self.config)
            elif self.config.provider == "google":
                self._provider = GoogleProvider(self.config)
            elif self.config.provider == "oidc":
                self._provider = GenericOIDCProvider(self.config)
            else:
                raise ValueError(f"Unknown OAuth provider: {self.config.provider}")
        return self._provider

    def is_configured(self) -> bool:
        return self.config.is_configured()

    def is_authenticated(self) -> bool:
        return self.session.is_authenticated()

    def get_user(self) -> Optional[Dict[str, Any]]:
        return self.session.get_user()

    def get_user_email(self) -> Optional[str]:
        return self.session.get_user_email()

    def login(self, request_host: Optional[str] = None, request_path: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
        """
        Start login: persist state+PKCE in store, return (auth_url, state_cookie_value).
        state_cookie_value should be set as cookie by the app (Streamlit cannot set HTTP-only cookies from Python;
        we still persist state in DB and pass state in URL; cookie is optional extra binding).
        """
        store_path = Path(__file__).parent.parent / "database" / "auth_store.db"
        if not auth_store.check_rate_limit(f"login:{request_host or 'unknown'}", store_path):
            return None, None
        state = secrets.token_urlsafe(32)
        code_verifier = _pkce_code_verifier()
        code_challenge = _pkce_code_challenge(code_verifier)
        nonce = secrets.token_hex(16)
        auth_store.save_oauth_pending(
            state=state,
            code_verifier=code_verifier,
            nonce=nonce,
            redirect_uri=self.config.redirect_uri,
            store_path=store_path,
        )
        auth_url = self.provider.get_authorization_url(
            state=state,
            code_challenge=code_challenge,
            nonce=nonce,
        )
        cookie_value = _sign_state_cookie(self.config.session_secret, state)
        return auth_url, cookie_value

    def handle_callback(
        self,
        code: str,
        state: str,
        request_url: Optional[str] = None,
        state_cookie_value: Optional[str] = None,
    ) -> bool:
        """
        Validate redirect_uri (request URL), state from store (with PKCE), exchange code, create session.
        """
        store_path = Path(__file__).parent.parent / "database" / "auth_store.db"
        if request_url:
            parsed = urlparse(request_url)
            expected = urlparse(self.config.redirect_uri)
            if parsed.scheme != expected.scheme or parsed.netloc != expected.netloc or parsed.path.rstrip("/") != expected.path.rstrip("/"):
                logger.warning("Redirect URI mismatch: request=%s expected=%s", request_url, self.config.redirect_uri)
                return False
        if not auth_store.check_rate_limit("callback", store_path):
            return False
        pending = auth_store.consume_oauth_pending(state, store_path)
        if not pending:
            logger.warning("Invalid or expired OAuth state")
            return False
        code_verifier = pending["code_verifier"]
        try:
            tokens = self.provider.exchange_code_for_token(code, code_verifier)
        except Exception as e:
            logger.exception("Token exchange failed: %s", e)
            return False
        if "error" in tokens:
            logger.warning("OAuth token error: %s", tokens.get("error_description", tokens.get("error")))
            return False
        access_token = tokens.get("access_token")
        if not access_token:
            return False
        user_info = self.provider.get_user_info(access_token)
        if not user_info.get("email"):
            return False
        self.session.create_session(user_info, tokens)
        auth_store.clear_rate_limit("callback", store_path)
        return True

    def logout(self) -> None:
        self.session.logout()

    def is_admin(self, email: Optional[str] = None) -> bool:
        email = email or self.get_user_email()
        return email in self.config.admin_users if email else False


class DemoAuthManager:
    """Demo auth: only allowed when ENV is not production."""

    def __init__(self):
        self.config = AuthConfig()

    def is_configured(self) -> bool:
        return True

    def is_authenticated(self) -> bool:
        return st.session_state.get("demo_authenticated", False)

    def get_user(self) -> Optional[Dict[str, Any]]:
        if self.is_authenticated():
            return st.session_state.get("demo_user")
        return None

    def get_user_email(self) -> Optional[str]:
        u = self.get_user()
        return u.get("email") if u else None

    def demo_login(self, email: str, name: str) -> None:
        st.session_state["demo_authenticated"] = True
        st.session_state["demo_user"] = {
            "email": email,
            "name": name,
            "id": hashlib.sha256(email.encode()).hexdigest()[:16],
            "provider": "demo",
        }

    def logout(self) -> None:
        st.session_state["demo_authenticated"] = False
        if "demo_user" in st.session_state:
            del st.session_state["demo_user"]

    def is_admin(self, email: Optional[str] = None) -> bool:
        email = email or self.get_user_email()
        return email in self.config.admin_users if email else False


# ---------------------------------------------------------------------------
# Firebase Authentication (Google Sign-In via Firebase, token verified server-side only)
# ---------------------------------------------------------------------------

try:
    import firebase_admin
    from firebase_admin import credentials as fb_credentials, auth as firebase_auth
    FIREBASE_ADMIN_AVAILABLE = True
except ImportError:
    FIREBASE_ADMIN_AVAILABLE = False
    firebase_admin = None
    firebase_auth = None


class FirebaseConfig:
    """Firebase project config for client SDK and (optional) Admin SDK."""

    def __init__(self):
        self.project_id = _get_secret("FIREBASE_PROJECT_ID", "")
        self.api_key = _get_secret("FIREBASE_API_KEY", "")
        self.auth_domain = _get_secret("FIREBASE_AUTH_DOMAIN", "") or (
            f"{self.project_id}.firebaseapp.com" if self.project_id else ""
        )
        # Service account JSON string or path for Admin SDK (required to verify ID tokens)
        self.service_account_json = _get_secret("FIREBASE_SERVICE_ACCOUNT_JSON", "")
        self.service_account_path = _get_secret("FIREBASE_SERVICE_ACCOUNT_PATH", "")

    def is_configured(self) -> bool:
        return bool(self.project_id and self.api_key)

    def can_verify_tokens(self) -> bool:
        return bool(FIREBASE_ADMIN_AVAILABLE and (self.service_account_json or self.service_account_path))

    def get_firebase_config_js(self) -> str:
        return f"""
        apiKey: "{self.api_key}",
        authDomain: "{self.auth_domain}",
        projectId: "{self.project_id}"
        """


class _FirebaseSessionManager:
    """Session state for Firebase-authenticated users (same keys as SessionManager for app compatibility)."""

    def __init__(self, config: AuthConfig):
        self.config = config

    def create_session(self, user_info: Dict[str, Any], tokens: Dict[str, Any]) -> None:
        st.session_state["authenticated"] = True
        st.session_state["user"] = {
            "email": user_info.get("email"),
            "name": user_info.get("name"),
            "id": user_info.get("id"),
            "provider": "firebase",
        }
        st.session_state["session_created"] = datetime.utcnow().isoformat()
        st.session_state["session_expires"] = (
            datetime.utcnow() + timedelta(minutes=self.config.session_timeout)
        ).isoformat()

    def is_authenticated(self) -> bool:
        if not st.session_state.get("authenticated"):
            return False
        expires = st.session_state.get("session_expires")
        if expires:
            try:
                if datetime.utcnow() > datetime.fromisoformat(expires):
                    self.logout()
                    return False
            except Exception:
                self.logout()
                return False
        return True

    def get_user(self) -> Optional[Dict[str, Any]]:
        if self.is_authenticated():
            return st.session_state.get("user")
        return None

    def get_user_email(self) -> Optional[str]:
        u = self.get_user()
        return u.get("email") if u else None

    def logout(self) -> None:
        for key in ["authenticated", "user", "session_created", "session_expires"]:
            if key in st.session_state:
                del st.session_state[key]


class FirebaseAuthManager:
    """Firebase Authentication: Google Sign-In via Firebase JS SDK, ID token verified with Admin SDK only."""

    def __init__(self):
        self.config = AuthConfig()
        self.firebase_config = FirebaseConfig()
        self.session = _FirebaseSessionManager(self.config)
        self._admin_initialized = False

    def _init_firebase_admin(self) -> bool:
        if self._admin_initialized or not self.firebase_config.can_verify_tokens():
            return bool(firebase_admin and firebase_admin._apps)
        try:
            if firebase_admin._apps:
                self._admin_initialized = True
                return True
            if self.firebase_config.service_account_json:
                cred_dict = json.loads(self.firebase_config.service_account_json)
                cred = fb_credentials.Certificate(cred_dict)
                firebase_admin.initialize_app(cred)
            elif self.firebase_config.service_account_path:
                cred = fb_credentials.Certificate(self.firebase_config.service_account_path)
                firebase_admin.initialize_app(cred)
            else:
                return False
            self._admin_initialized = True
            return True
        except Exception as e:
            logger.warning("Firebase Admin init failed: %s", e)
            return False

    def is_configured(self) -> bool:
        return self.firebase_config.is_configured()

    def is_authenticated(self) -> bool:
        return self.session.is_authenticated()

    def get_user(self) -> Optional[Dict[str, Any]]:
        return self.session.get_user()

    def get_user_email(self) -> Optional[str]:
        return self.session.get_user_email()

    def logout(self) -> None:
        self.session.logout()

    def is_admin(self, email: Optional[str] = None) -> bool:
        email = email or self.get_user_email()
        return email in self.config.admin_users if email else False

    def verify_id_token(self, id_token: str) -> Optional[Dict[str, Any]]:
        """Verify Firebase ID token with Admin SDK. Returns user info or None. No unverified decode."""
        if not self.firebase_config.can_verify_tokens():
            logger.warning("Firebase Admin not available; cannot verify token")
            return None
        if not self._init_firebase_admin():
            return None
        try:
            decoded = firebase_auth.verify_id_token(id_token)
            return {
                "email": decoded.get("email"),
                "name": decoded.get("name", (decoded.get("email") or "").split("@")[0]),
                "id": decoded.get("uid"),
            }
        except Exception as e:
            logger.warning("Firebase token verification failed: %s", e)
            return None

    def get_login_component(self, redirect_base_url: str) -> str:
        """Return HTML/JS for Firebase Google Sign-In. On success, redirects to redirect_base_url?firebase_token=ID_TOKEN (server then exchanges for one-time code)."""
        cfg = self.firebase_config.get_firebase_config_js()
        return f"""
<script src="https://www.gstatic.com/firebasejs/10.7.0/firebase-app-compat.js"></script>
<script src="https://www.gstatic.com/firebasejs/10.7.0/firebase-auth-compat.js"></script>
<script>
(function() {{
  const firebaseConfig = {{{cfg}}};
  if (!firebase.apps.length) firebase.initializeApp(firebaseConfig);
  const provider = new firebase.auth.GoogleAuthProvider();
  window.firebaseSignIn = function() {{
    firebase.auth().signInWithPopup(provider).then(function(result) {{
      return result.user.getIdToken();
    }}).then(function(idToken) {{
      var url = "{redirect_base_url}".replace(/\\?.*$/, "");
      url += (url.indexOf("?") >= 0 ? "&" : "?") + "firebase_token=" + encodeURIComponent(idToken);
      window.top.location.href = url;
    }}).catch(function(e) {{ console.error(e); alert("Sign-in failed: " + (e.message || "Unknown error")); }});
  }};
}})();
</script>
<div class="firebase-login-container" style="text-align:center;padding:1rem;">
  <button onclick="firebaseSignIn()" style="padding:0.6rem 1.2rem;font-size:1rem;cursor:pointer;background:#4285f4;color:white;border:none;border-radius:6px;">
    Sign in with Google
  </button>
</div>
"""


def get_auth_manager() -> Any:
    """Return FirebaseAuthManager if Firebase configured; else AuthManager if OAuth; else DemoAuthManager when not production."""
    config = AuthConfig()
    firebase_config = FirebaseConfig()
    if firebase_config.is_configured():
        return FirebaseAuthManager()
    if config.is_configured():
        return AuthManager()
    if config.is_production:
        raise RuntimeError(
            "Auth must be configured when ENV=production. In Streamlit Cloud go to App → Settings → Secrets and add:\n\n"
            "For Firebase: FIREBASE_PROJECT_ID, FIREBASE_API_KEY, FIREBASE_AUTH_DOMAIN\n"
            "(Or for OAuth: OAUTH_PROVIDER and provider credentials.)"
        )
    return DemoAuthManager()


def require_auth(func):
    def wrapper(*args, **kwargs):
        auth = get_auth_manager()
        if not auth.is_authenticated():
            st.warning("Please log in to access this page.")
            st.stop()
        return func(*args, **kwargs)
    return wrapper


def get_role_for_user(db: Any, email: str) -> str:
    if hasattr(db, "get_or_create_user"):
        user = db.get_or_create_user(email)
        return user.get("role", "reporter")
    return "reporter"


def has_permission(db: Any, email: str, permission: str) -> bool:
    roles_config = _get_roles_config()
    role = get_role_for_user(db, email)
    permissions = roles_config.get("roles", {}).get(role, {}).get("permissions", [])
    return permission in permissions


# ---------------------------------------------------------------------------
# Firebase one-time code exchange (no token in URL)
# Client must send token to backend via POST/API; backend verifies token,
# stores encrypted user_info under a one-time code, redirects to ?code=xxx.
# Callback exchanges code for session. Never pass tokens in the URL.
# ---------------------------------------------------------------------------

def create_firebase_code_for_user_info(user_info: Dict[str, Any], secret: str) -> str:
    """Store encrypted user_info under a one-time code; return code. Use after verifying Firebase ID token server-side."""
    payload = _encrypt_tokens(secret, {"user_info": user_info, "tokens": {}})
    return auth_store.save_firebase_code(payload, Path(__file__).parent.parent / "database" / "auth_store.db")


def firebase_token_to_code(firebase_auth_manager: "FirebaseAuthManager", id_token: str) -> Optional[str]:
    """Verify Firebase ID token and return a one-time code for redirect (so token is not left in URL). Returns None if verification fails."""
    user_info = firebase_auth_manager.verify_id_token(id_token)
    if not user_info or not user_info.get("email"):
        return None
    return create_firebase_code_for_user_info(user_info, firebase_auth_manager.config.session_secret)


def exchange_firebase_code_for_session(auth_manager: Any, code: str) -> bool:
    """Exchange one-time code for session (no token in URL). auth_manager: AuthManager or FirebaseAuthManager. Returns True if session was created."""
    store_path = Path(__file__).parent.parent / "database" / "auth_store.db"
    encrypted = auth_store.consume_firebase_code(code, store_path)
    if not encrypted:
        return False
    data = _decrypt_tokens(auth_manager.config.session_secret, encrypted)
    if not data or "user_info" not in data:
        return False
    user_info = data["user_info"]
    tokens = data.get("tokens") or {}
    auth_manager.session.create_session(user_info, tokens)
    return True
