"""
Diagnexia Incident Management - Main entry point.
Uses security-hardened OAuth (PKCE, state in store, encrypted tokens, rate limiting).
Supports deployment on Streamlit Community Cloud; OAuth for public access.
"""

import os
import csv
import io
import json
from pathlib import Path
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
    # Force auth-related keys from st.secrets so they are never empty when set in Cloud
    force_keys = (
        "FIREBASE_PROJECT_ID", "FIREBASE_API_KEY", "FIREBASE_AUTH_DOMAIN",
        "SESSION_SECRET_KEY", "ENV",
        "OAUTH_PROVIDER", "OAUTH_REDIRECT_URI", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET",
    )
    for key in force_keys:
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
from modules import incidents

# Initialize auth (Firebase, OAuth, or demo)
try:
    auth = get_auth_manager()
except RuntimeError as e:
    st.error(str(e))
    st.stop()


def _build_callback_request_url() -> str | None:
    """Build the current request URL for redirect_uri validation if possible."""
    try:
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
    """Handle OAuth callback: validate, exchange code with PKCE, create session."""
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
        st.error("Authentication failed. Please try again.")
        st.query_params.clear()
    return success


def show_login_page():
    """Show login: Firebase Google Sign-In, OAuth redirect, or demo form."""
    st.markdown("# Diagnexia Incident Management")
    st.markdown("Digital Pathology Incident Logging Framework")
    if isinstance(auth, FirebaseAuthManager):
        st.markdown("Sign in with your Google account.")
        html = auth.get_login_component("")
        st.components.v1.html(html, height=80)
        return
    if auth.is_configured():
        if isinstance(auth, AuthManager):
            request_host = None
            auth_url, state_cookie_value = auth.login(request_host=request_host, request_path="/")
            if not auth_url:
                st.error("Too many login attempts. Please try again later.")
                return
            st.markdown("Sign in with your organization account.")
            st.link_button("Sign in", auth_url, type="primary")
    else:
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


# ---------------------------------------------------------------------------
# Decision tree config
# ---------------------------------------------------------------------------
DECISION_TREE_PATH = Path(__file__).resolve().parent / "config" / "decision_tree.json"


def _load_decision_tree():
    if not DECISION_TREE_PATH.exists():
        return None
    with open(DECISION_TREE_PATH, encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Dashboard: Incident log
# ---------------------------------------------------------------------------
def _show_incident_log():
    st.subheader("Incident log")
    st.markdown("Log and track digital pathology incidents.")

    user = auth.get_user()
    reported_by = user.get("name") or ""
    reported_by_email = user.get("email") or ""

    with st.expander("➕ Log a new incident", expanded=True):
        with st.form("new_incident"):
            title = st.text_input("Title *", placeholder="Short description of the incident")
            description = st.text_area("Description", placeholder="What happened? When? Where?")
            col1, col2 = st.columns(2)
            with col1:
                incident_type = st.selectbox(
                    "Incident type *",
                    ["Specimen / sample", "Imaging / slide quality", "Workflow / process", "Equipment / system", "Safety / compliance", "Other"],
                )
            with col2:
                severity = st.selectbox(
                    "Severity *",
                    ["Low", "Medium", "High", "Critical"],
                )
            if st.form_submit_button("Submit incident"):
                if not title or not incident_type or not severity:
                    st.warning("Please fill in at least title, type, and severity.")
                else:
                    incidents.create_incident(
                        title=title,
                        description=description,
                        incident_type=incident_type,
                        severity=severity,
                        reported_by=reported_by,
                        reported_by_email=reported_by_email,
                    )
                    st.success("Incident logged.")
                    st.rerun()

    st.markdown("---")
    st.markdown("**Recent incidents**")
    filter_status = st.selectbox("Filter by status", ["All", "open", "in_progress", "resolved", "closed"], key="filter_status")
    filter_type = st.selectbox("Filter by type", ["All", "Specimen / sample", "Imaging / slide quality", "Workflow / process", "Equipment / system", "Safety / compliance", "Other"], key="filter_type")
    filter_severity = st.selectbox("Filter by severity", ["All", "Low", "Medium", "High", "Critical"], key="filter_severity")

    status_arg = None if filter_status == "All" else filter_status
    type_arg = None if filter_type == "All" else filter_type
    severity_arg = None if filter_severity == "All" else filter_severity

    rows = incidents.list_incidents(status=status_arg, incident_type=type_arg, severity=severity_arg)
    if not rows:
        st.info("No incidents match the filters.")
        return

    for inc in rows:
        with st.container():
            col1, col2, col3 = st.columns([3, 1, 1])
            with col1:
                st.markdown(f"**{inc['title']}** — {inc['incident_type']} · {inc['severity']} · {inc['status']}")
                if inc.get("description"):
                    st.caption(inc["description"][:200] + ("..." if len(inc.get("description", "")) > 200 else ""))
                st.caption(f"Reported by {inc.get('reported_by') or inc.get('reported_by_email') or '—'} on {inc.get('reported_at', '')[:10]}")
            with col2:
                if inc["status"] == "open" or inc["status"] == "in_progress":
                    new_status = st.selectbox(
                        "Update status",
                        ["open", "in_progress", "resolved", "closed"],
                        index=["open", "in_progress", "resolved", "closed"].index(inc["status"]),
                        key=f"status_{inc['id']}",
                    )
                    if new_status != inc["status"]:
                        if st.button("Save", key=f"save_{inc['id']}"):
                            incidents.update_incident_status(inc["id"], new_status)
                            st.rerun()
            st.markdown("---")


# ---------------------------------------------------------------------------
# Dashboard: Decision support (fast-track)
# ---------------------------------------------------------------------------
def _show_decision_support():
    tree = _load_decision_tree()
    if not tree:
        st.subheader("Decision support")
        st.info("Decision tree config not found. Add config/decision_tree.json.")
        return

    st.subheader("Decision support")
    st.markdown(tree.get("description", "Answer a few questions to get recommended actions and next steps."))
    st.markdown("---")

    types = tree.get("incident_types", [])
    severities = tree.get("severity_levels", [])
    recs = tree.get("recommendations", {})

    type_labels = [t["label"] for t in types]
    type_ids = [t["id"] for t in types]
    chosen_type_label = st.radio("**1. What type of incident is it?**", type_labels, key="dt_type")
    chosen_type_id = type_ids[type_labels.index(chosen_type_label)]

    severity_labels = [s["label"] for s in severities]
    severity_ids = [s["id"] for s in severities]
    chosen_severity_label = st.radio("**2. What is the severity?**", severity_labels, key="dt_severity")
    chosen_severity_id = severity_ids[severity_labels.index(chosen_severity_label)]

    st.markdown("---")
    st.markdown("### Recommended actions")
    steps = recs.get(chosen_type_id, recs.get("other", {})).get(chosen_severity_id, ["Log the incident and notify your supervisor."])
    for i, step in enumerate(steps, 1):
        st.markdown(f"{i}. {step}")
    st.success("Use the Incident log to record this incident and track progress.")


# ---------------------------------------------------------------------------
# Dashboard: Reports
# ---------------------------------------------------------------------------
def _show_reports():
    st.subheader("Reports")
    st.markdown("View and export incident data.")

    rows = incidents.list_incidents()
    if not rows:
        st.info("No incidents yet. Log incidents in the Incident log.")
        return

    # Simple table
    display = []
    for r in rows:
        display.append({
            "ID": r.get("id"),
            "Title": r.get("title"),
            "Type": r.get("incident_type"),
            "Severity": r.get("severity"),
            "Status": r.get("status"),
            "Reported by": r.get("reported_by") or r.get("reported_by_email"),
            "Reported at": (r.get("reported_at") or "")[:10],
        })
    st.dataframe(display, use_container_width=True, hide_index=True)

    # Export CSV
    st.markdown("---")
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=["ID", "Title", "Type", "Severity", "Status", "Reported by", "Reported at"])
    w.writeheader()
    w.writerows(display)
    csv_content = buf.getvalue()
    st.download_button(
        "Download CSV",
        data=csv_content,
        file_name="incidents_export.csv",
        mime="text/csv",
        key="dl_csv",
    )


def show_dashboard():
    """Dashboard: welcome, sidebar nav, and selected page (Incident log, Decision support, Reports)."""
    user = auth.get_user()
    st.sidebar.markdown(f"**{user.get('name') or user.get('email')}**")
    if auth.is_admin():
        st.sidebar.caption("(Admin)")
    st.sidebar.markdown("---")

    page = st.sidebar.radio(
        "Go to",
        ["Incident log", "Decision support", "Reports"],
        label_visibility="collapsed",
    )

    if page == "Incident log":
        _show_incident_log()
    elif page == "Decision support":
        _show_decision_support()
    else:
        _show_reports()

    st.sidebar.markdown("---")
    if st.sidebar.button("Sign out"):
        auth.logout()
        st.rerun()


def main():
    q = st.query_params

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

    if isinstance(auth, FirebaseAuthManager) and "code" in q and "firebase_token" not in q:
        if exchange_firebase_code_for_session(auth, q["code"]):
            st.query_params.clear()
            st.rerun()
        else:
            st.error("Sign-in failed. Please try again.")
            st.query_params.clear()
        return

    if isinstance(auth, AuthManager) and "code" in q and "state" in q:
        handle_oauth_callback()
        return

    if auth.is_authenticated():
        show_dashboard()
    else:
        show_login_page()


if __name__ == "__main__":
    main()
