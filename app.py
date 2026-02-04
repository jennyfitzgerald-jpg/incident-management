"""
Diagnexia Incident Management - Main entry point.
Uses security-hardened OAuth (PKCE, state in store, encrypted tokens, rate limiting).
Supports deployment on Streamlit Community Cloud; OAuth for public access.
"""

import os
import streamlit as st
from dotenv import load_dotenv

# Load .env for local development
load_dotenv()

# On Streamlit Community Cloud (and similar), secrets are in st.secrets — copy into os.environ
# so AuthConfig and modules read them. setdefault so .env wins when both exist.
if hasattr(st, "secrets") and st.secrets:
    for key, value in st.secrets.items():
        if isinstance(value, (str, int, float, bool)):
            os.environ.setdefault(key, str(value))
        elif isinstance(value, dict):
            for sub_key, sub_value in value.items():
                if isinstance(sub_value, (str, int, float, bool)):
                    os.environ.setdefault(sub_key, str(sub_value))
    # Force Firebase (and auth) keys from st.secrets so they are never empty when set in Cloud
    for key in ("FIREBASE_PROJECT_ID", "FIREBASE_API_KEY", "FIREBASE_AUTH_DOMAIN", "SESSION_SECRET_KEY", "ENV"):
        try:
            if key in st.secrets and st.secrets[key] not in (None, ""):
                os.environ[key] = str(st.secrets[key])
        except Exception:
            pass

st.set_page_config(
    page_title="Diagnexia Incident Management",
    page_icon="🏥",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Lazy import so AuthConfig is only evaluated after load_dotenv
from modules.auth import (
    get_auth_manager,
    AuthConfig,
    AuthManager,
    FirebaseAuthManager,
    firebase_token_to_code,
    exchange_firebase_code_for_session,
)

# Initialize auth (Firebase, OAuth, or demo)
try:
    auth = get_auth_manager()
except RuntimeError as e:
    st.error(str(e))
    st.stop()


def _build_callback_request_url() -> str | None:
    """Build the current request URL for redirect_uri validation if possible."""
    try:
        # Streamlit 1.30+ may expose request; fallback to env
        from streamlit.runtime.scriptrunner_utils.script_run_context import get_script_run_ctx
        ctx = get_script_run_ctx()
        if ctx and hasattr(ctx, "request") and ctx.request:
            req = ctx.request
            if hasattr(req, "url"):
                return req.url
    except Exception:
        pass
    return None


def handle_oauth_callback() -> bool:
    """Handle OAuth callback: validate, exchange code with PKCE, create session. Generic user message on failure."""
    query_params = st.query_params
    if "code" not in query_params or "state" not in query_params:
        return False
    code = query_params["code"]
    state = query_params["state"]
    if not isinstance(auth, AuthManager):
        return False
    request_url = _build_callback_request_url()
    success = auth.handle_callback(code=code, state=state, request_url=request_url)
    if success:
        st.query_params.clear()
        st.rerun()
    else:
        # Generic message only; details are logged server-side
        st.error("Authentication failed. Please try again.")
        st.query_params.clear()
    return success


def show_login_page():
    """Show login: Firebase Google Sign-In, OAuth redirect, or demo form (only when not production)."""
    st.markdown("# Diagnexia Incident Management")
    st.markdown("Digital Pathology Incident Logging Framework")
    if isinstance(auth, FirebaseAuthManager):
        # Firebase: render Google Sign-In button (HTML/JS). Redirect uses current page URL so no secret needed.
        st.markdown("Sign in with your Google account.")
        html = auth.get_login_component("")  # empty = use browser's current URL for redirect
        st.components.v1.html(html, height=80)
        return
    if auth.is_configured():
        # OAuth: start flow (state + PKCE in store, rate-limited)
        if isinstance(auth, AuthManager):
            request_host = None
            auth_url, state_cookie_value = auth.login(request_host=request_host, request_path="/")
            if not auth_url:
                st.error("Too many login attempts. Please try again later.")
                return
            st.markdown("Sign in with your organization account.")
            st.link_button("Sign in", auth_url, type="primary")
    else:
        # Demo mode (only when ENV != production)
        st.info("Demo mode: OAuth is not configured.")
        with st.form("demo_login"):
            email = st.text_input("Email")
            name = st.text_input("Name")
            if st.form_submit_button("Sign in"):
                if email and name:
                    auth.demo_login(email, name)
                    st.rerun()
                else:
                    st.warning("Please enter email and name.")


def show_dashboard():
    """Dashboard after login: welcome, navigation placeholders, sign out."""
    user = auth.get_user()
    st.markdown(f"Welcome, **{user.get('name') or user.get('email')}**")
    if auth.is_admin():
        st.caption("(Admin)")
    st.markdown("---")

    st.subheader("Incident log")
    st.markdown("Log and track digital pathology incidents. *(Add your incident form and list here.)*")
    st.markdown("---")

    st.subheader("Decision support")
    st.markdown("Tools and guidance for incident handling. *(Add decision trees or workflows here.)*")
    st.markdown("---")

    st.subheader("Reports")
    st.markdown("View and export incident reports. *(Add reporting module here.)*")

    st.markdown("---")
    if st.button("Sign out"):
        auth.logout()
        st.rerun()


def main():
    q = st.query_params

    # Firebase: token in URL once -> verify, create one-time code, redirect to ?code= (token removed)
    if isinstance(auth, FirebaseAuthManager) and "firebase_token" in q:
        token = q.get("firebase_token")
        if token:
            code = firebase_token_to_code(auth, token)
            if code:
                st.query_params["code"] = code
                del st.query_params["firebase_token"]
                st.rerun()
            else:
                st.error("Sign-in failed. Please try again.")
                st.query_params.clear()
        return

    # Firebase: one-time code -> exchange for session
    if isinstance(auth, FirebaseAuthManager) and "code" in q and "firebase_token" not in q:
        if exchange_firebase_code_for_session(auth, q["code"]):
            st.query_params.clear()
            st.rerun()
        else:
            st.error("Sign-in failed. Please try again.")
            st.query_params.clear()
        return

    # OAuth callback (code + state)
    if isinstance(auth, AuthManager) and "code" in q and "state" in q:
        handle_oauth_callback()
        return

    if auth.is_authenticated():
        show_dashboard()
    else:
        show_login_page()


if __name__ == "__main__":
    main()
