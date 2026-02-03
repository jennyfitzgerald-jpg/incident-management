"""
Tests for auth_store and auth module (no live OAuth provider needed).
Run from project root: python -m pytest tests/test_auth.py -v
Or: python tests/test_auth.py
"""

import os
import sys
import tempfile
import time
from pathlib import Path

# Project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Mock Streamlit before any auth import that uses st
import unittest.mock as mock
_st_session = {}
_st = mock.MagicMock()
_st.session_state = _st_session
_st.query_params = {}
_st.experimental_get_query_params = lambda: {}
sys.modules["streamlit"] = _st


def test_auth_store_oauth_pending():
    """OAuth state and PKCE save/consume."""
    from modules import auth_store as store_mod
    with tempfile.TemporaryDirectory() as tmp:
        store = Path(tmp) / "auth.db"
        store_mod.init_store(store)
        store_mod.save_oauth_pending(
            state="abc123",
            code_verifier="verifier456",
            nonce="n789",
            redirect_uri="http://localhost:8501/callback",
            store_path=store,
        )
        out = store_mod.consume_oauth_pending("abc123", store_path=store)
        assert out is not None
        assert out["code_verifier"] == "verifier456"
        assert out["nonce"] == "n789"
        assert out["redirect_uri"] == "http://localhost:8501/callback"
        # Consume again -> gone
        assert store_mod.consume_oauth_pending("abc123", store_path=store) is None


def test_auth_store_firebase_code():
    """One-time code exchange for Firebase (no token in URL)."""
    from modules import auth_store as store_mod
    with tempfile.TemporaryDirectory() as tmp:
        store = Path(tmp) / "auth.db"
        store_mod.init_store(store)
        code = store_mod.save_firebase_code("encrypted_payload_here", store_path=store)
        assert isinstance(code, str) and len(code) > 10
        payload = store_mod.consume_firebase_code(code, store_path=store)
        assert payload == "encrypted_payload_here"
        assert store_mod.consume_firebase_code(code, store_path=store) is None


def test_auth_store_rate_limit():
    """Rate limit allows under threshold, blocks over."""
    from modules import auth_store as store_mod
    with tempfile.TemporaryDirectory() as tmp:
        store = Path(tmp) / "auth.db"
        store_mod.init_store(store)
        key = "test_key_" + str(time.time())
        for _ in range(store_mod.RATE_LIMIT_MAX_ATTEMPTS):
            assert store_mod.check_rate_limit(key, store_path=store) is True
        assert store_mod.check_rate_limit(key, store_path=store) is False
        store_mod.clear_rate_limit(key, store_path=store)
        assert store_mod.check_rate_limit(key, store_path=store) is True


def test_auth_config_and_pkce_helpers():
    """AuthConfig and PKCE/sign helpers without Streamlit dependency."""
    # Use helpers that don't need full auth import (avoid st in SessionManager)
    from modules.auth import (
        _pkce_code_verifier,
        _pkce_code_challenge,
        _sign_state_cookie,
        _verify_state_cookie,
        AuthConfig,
    )
    verifier = _pkce_code_verifier()
    assert 43 <= len(verifier) <= 128
    challenge = _pkce_code_challenge(verifier)
    assert len(challenge) > 0 and "=" not in challenge
    secret = "test_secret_key_32chars_long!!!!"
    signed = _sign_state_cookie(secret, "mystate")
    assert _verify_state_cookie(secret, signed) == "mystate"
    assert _verify_state_cookie(secret, "mystate.badsig") is None
    assert _verify_state_cookie("other", signed) is None
    # AuthConfig with clean env
    with mock.patch.dict(os.environ, {"ENV": "development"}, clear=False):
        cfg = AuthConfig()
        assert cfg.is_production is False
        assert cfg.session_secret  # has random default when not production
    with mock.patch.dict(os.environ, {"ENV": "production", "SESSION_SECRET_KEY": "fixed_secret_32_chars!!!!!!"}, clear=False):
        cfg = AuthConfig()
        assert cfg.is_production is True
        assert cfg.session_secret == "fixed_secret_32_chars!!!!!!"


def test_get_auth_manager_demo_vs_production():
    """Demo mode when ENV=development and no OAuth; production requires OAuth."""
    from modules.auth import get_auth_manager, DemoAuthManager, AuthManager
    # Demo when not configured and not production
    with mock.patch.dict(os.environ, {"ENV": "development", "OAUTH_PROVIDER": "azure", "AZURE_CLIENT_ID": "", "AZURE_CLIENT_SECRET": "", "AZURE_TENANT_ID": ""}, clear=False):
        auth = get_auth_manager()
        assert isinstance(auth, DemoAuthManager)
    # Production without OAuth -> should raise
    with mock.patch.dict(os.environ, {"ENV": "production", "OAUTH_PROVIDER": "azure", "AZURE_CLIENT_ID": "", "AZURE_CLIENT_SECRET": "", "AZURE_TENANT_ID": ""}, clear=False):
        try:
            get_auth_manager()
            assert False, "expected RuntimeError"
        except RuntimeError as e:
            assert "OAuth" in str(e) or "production" in str(e)
    # OAuth configured (need SESSION_SECRET_KEY)
    with mock.patch.dict(
        os.environ,
        {
            "ENV": "development",
            "OAUTH_PROVIDER": "google",
            "GOOGLE_CLIENT_ID": "cid",
            "GOOGLE_CLIENT_SECRET": "csec",
            "SESSION_SECRET_KEY": "secret_32_chars!!!!!!!!!!!!!!!!",
        },
        clear=False,
    ):
        auth = get_auth_manager()
        assert isinstance(auth, AuthManager)
        assert auth.is_configured() is True


def test_demo_login_logout():
    """Demo login and logout set/clear session state."""
    from modules.auth import get_auth_manager, DemoAuthManager
    _st_session.clear()
    with mock.patch.dict(os.environ, {"ENV": "development", "OAUTH_PROVIDER": "azure", "AZURE_CLIENT_ID": "", "AZURE_CLIENT_SECRET": "", "AZURE_TENANT_ID": "", "ADMIN_USERS": ""}, clear=False):
        auth = get_auth_manager()
        assert isinstance(auth, DemoAuthManager)
        assert not auth.is_authenticated()
        auth.demo_login("test@example.com", "Test User")
        assert auth.is_authenticated()
        u = auth.get_user()
        assert u["email"] == "test@example.com"
        assert u["name"] == "Test User"
        auth.logout()
        assert not auth.is_authenticated()
        assert auth.get_user() is None


def test_oauth_login_returns_url_and_state_cookie():
    """Login with OAuth configured returns auth URL and signed state value."""
    from modules.auth import get_auth_manager, AuthManager
    _st_session.clear()
    with mock.patch.dict(
        os.environ,
        {
            "ENV": "development",
            "OAUTH_PROVIDER": "google",
            "GOOGLE_CLIENT_ID": "test-client-id",
            "GOOGLE_CLIENT_SECRET": "test-secret",
            "SESSION_SECRET_KEY": "test_session_secret_32_chars!!!!!!",
            "OAUTH_REDIRECT_URI": "http://localhost:8501/callback",
        },
        clear=False,
    ):
        auth = get_auth_manager()
        auth_url, cookie_val = auth.login(request_host="localhost")
    assert auth_url is not None
    assert "accounts.google.com" in auth_url
    assert "code_challenge=" in auth_url
    assert "state=" in auth_url
    assert cookie_val is not None
    assert "." in cookie_val


def test_encrypt_decrypt_tokens():
    """Token encryption roundtrip."""
    import json
    from modules.auth import _encrypt_tokens, _decrypt_tokens
    secret = "my_secret_key_32_characters_long!!!"
    tokens = {"access_token": "at", "refresh_token": "rt", "expires_in": 3600}
    enc = _encrypt_tokens(secret, tokens)
    assert enc != json.dumps(tokens) or "cryptography" in str(sys.modules.get("cryptography", ""))
    dec = _decrypt_tokens(secret, enc)
    assert dec == tokens
    assert _decrypt_tokens("wrong_key", enc) is None


def run_all():
    """Run tests and print results."""
    tests = [
        ("auth_store oauth_pending", test_auth_store_oauth_pending),
        ("auth_store firebase code", test_auth_store_firebase_code),
        ("auth_store rate_limit", test_auth_store_rate_limit),
        ("auth config and PKCE", test_auth_config_and_pkce_helpers),
        ("get_auth_manager demo vs production", test_get_auth_manager_demo_vs_production),
        ("demo login/logout", test_demo_login_logout),
        ("oauth login returns URL", test_oauth_login_returns_url_and_state_cookie),
        ("encrypt/decrypt tokens", test_encrypt_decrypt_tokens),
    ]
    failed = []
    for name, fn in tests:
        try:
            fn()
            print(f"  OK  {name}")
        except Exception as e:
            print(f"  FAIL {name}: {e}")
            failed.append((name, e))
    if failed:
        print(f"\n{len(failed)} test(s) failed.")
        sys.exit(1)
    print(f"\nAll {len(tests)} tests passed.")
    return 0


if __name__ == "__main__":
    run_all()
