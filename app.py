"""
Diagnexia Incident Management - Main entry point.
Uses security-hardened OAuth (PKCE, state in store, encrypted tokens, rate limiting).
Supports deployment on Streamlit Community Cloud; OAuth for public access.
"""

import os
import csv
import io
import json
import time
from pathlib import Path
import streamlit as st
from dotenv import load_dotenv

# #region agent log
def _debug_log(location: str, message: str, data: dict = None, hypothesis_id: str = None):
    payload = {"sessionId": "debug-session", "runId": "run1", "location": location, "message": message, "timestamp": int(time.time() * 1000)}
    if data is not None:
        payload["data"] = data
    if hypothesis_id:
        payload["hypothesisId"] = hypothesis_id
    line = json.dumps(payload) + "\n"
    for log_path in [
        Path(__file__).resolve().parent / ".cursor" / "debug.log",
        Path(os.getcwd()) / ".cursor" / "debug.log",
    ]:
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(line)
            break
        except Exception:
            continue
# #endregion

# Load .env for local development (from cwd and from app directory)
load_dotenv()
load_dotenv(Path(__file__).resolve().parent / ".env")

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
        "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
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
from modules import ai_incident
from modules import escalation

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


def _get_decision_tree_recommendations(incident_type_label: str, severity_label: str) -> list:
    """
    Return list of recommendation strings from decision_tree.json for the given type and severity.
    Maps app labels to tree ids (e.g. 'Specimen / sample' -> specimen, 'Low' -> low).
    """
    tree = _load_decision_tree()
    if not tree or not isinstance(tree.get("recommendations"), dict):
        return []
    recs = tree["recommendations"]
    type_id = "other"
    for t in tree.get("incident_types") or []:
        label = (t.get("label") or "").strip()
        if not label:
            continue
        if incident_type_label == label or (incident_type_label and (incident_type_label in label or label.startswith(incident_type_label))):
            type_id = t.get("id") or "other"
            break
    severity_id = (severity_label or "").strip().lower() or "low"
    by_type = recs.get(type_id)
    if not isinstance(by_type, dict):
        return []
    actions = by_type.get(severity_id)
    if isinstance(actions, list):
        return [str(a).strip() for a in actions if a]
    return []


# ---------------------------------------------------------------------------
# Dashboard: Incident log
# ---------------------------------------------------------------------------
INCIDENT_TYPES = ["Specimen / sample", "Imaging / slide quality", "Workflow / process", "Equipment / system", "Safety / compliance", "Other"]
SEVERITIES = ["Low", "Medium", "High", "Critical"]
JURISDICTIONS = escalation.get_jurisdictions() if hasattr(escalation, "get_jurisdictions") else ["UK", "US"]


def _show_incident_log():
    # #region agent log
    _debug_log("app.py:_show_incident_log", "Entry", {}, "H1")
    # #endregion
    st.subheader("Incident log")
    st.markdown("Log and track digital pathology incidents.")

    user = auth.get_user()
    reported_by = user.get("name") or ""
    reported_by_email = user.get("email") or ""
    # #region agent log
    _debug_log("app.py:_show_incident_log", "After get_user", {"has_user": bool(user)}, "H2")
    # #endregion

    # ---- Single "Log incident" entry: one summary + jurisdiction + one button (always first) ----
    ai_status = ai_incident.get_ai_status()
    st.caption(f"**LLM status:** {ai_status}" + (" — one-step AI flow is available." if ai_status != "Not configured" else " — set OPENAI_API_KEY or ANTHROPIC_API_KEY in `.env` (local) or Streamlit Secrets (deploy) to enable."))
    st.info("**One-step logging:** Enter a short summary in the box below (1–2 sentences), choose jurisdiction, then click **Log incident**. AI will classify type and severity and generate a formal report. No need to fill type or severity manually.")
    if not ai_incident.is_ai_configured():
        st.warning("Set **ANTHROPIC_API_KEY** or **OPENAI_API_KEY** in Secrets (or `.env` locally) to enable the smart flow. Until then, use **Advanced — Log manually** at the bottom of this page.")
    # #region agent log
    _debug_log("app.py:_show_incident_log", "About to render summary text_area", {}, "H2")
    # #endregion
    quick_text = st.text_area(
        "Describe what happened (one or two sentences)",
        placeholder="e.g. Slide 45 mislabeled, wrong block, found at QC in the UK lab.",
        key="quick_log_text",
        height=120,
        label_visibility="visible",
    )
    quick_jurisdiction = st.selectbox("Jurisdiction", JURISDICTIONS, key="quick_jurisdiction")
    # #region agent log
    _debug_log("app.py:_show_incident_log", "After summary text_area and jurisdiction", {"jurisdictions_count": len(JURISDICTIONS)}, "H3")
    # #endregion
    if st.button("Log incident", type="primary", key="quick_log_btn"):
        if not quick_text or not quick_text.strip():
            st.warning("Please enter a short description.")
        elif not ai_incident.is_ai_configured():
            st.warning("AI is not configured. Use the **Advanced — Log manually** form at the bottom of this page.")
        else:
            with st.spinner("AI is classifying, logging, and generating the formal report…"):
                incident_id, inc_dict, report_text, flagged = ai_incident.quick_log_incident(
                    quick_text,
                    jurisdiction_fallback=quick_jurisdiction,
                    reported_by=reported_by,
                    reported_by_email=reported_by_email,
                    create_incident_fn=lambda t, d, typ, sev, rb, rbe, j: incidents.create_incident(
                        title=t, description=d, incident_type=typ, severity=sev,
                        reported_by=rb, reported_by_email=rbe, jurisdiction=j,
                    ),
                    update_report_fn=incidents.update_incident_formal_report,
                    get_flagged_fn=escalation.get_flagged_for,
                    get_recommendations_fn=_get_decision_tree_recommendations,
                )
            if incident_id is not None:
                st.success(f"**Incident #{incident_id}** logged. Type: {inc_dict.get('incident_type')} · Severity: {inc_dict.get('severity')} · Jurisdiction: {inc_dict.get('jurisdiction')}.")
                if flagged:
                    st.caption("**Flagged for:** " + ", ".join(flagged))
                if report_text:
                    with st.expander("Formal report (auto-generated)", expanded=True):
                        st.text_area("Report", value=report_text, height=220, key="quick_report_preview", disabled=True)
                        st.caption("You can edit this in the incident list under « View / Edit formal report ».")
            else:
                st.error("Something went wrong. Try **Advanced — Log manually** at the bottom of this page.")

    st.markdown("---")
    st.markdown("**Recent incidents**")
    filter_status = st.selectbox("Filter by status", ["All", "open", "in_progress", "resolved", "closed"], key="filter_status")
    filter_type = st.selectbox("Filter by type", ["All"] + INCIDENT_TYPES, key="filter_type")
    filter_severity = st.selectbox("Filter by severity", ["All"] + SEVERITIES, key="filter_severity")
    filter_jurisdiction = st.selectbox("Filter by jurisdiction", ["All"] + JURISDICTIONS, key="filter_jurisdiction")

    status_arg = None if filter_status == "All" else filter_status
    type_arg = None if filter_type == "All" else filter_type
    severity_arg = None if filter_severity == "All" else filter_severity
    jurisdiction_arg = None if filter_jurisdiction == "All" else filter_jurisdiction

    rows = incidents.list_incidents(status=status_arg, incident_type=type_arg, severity=severity_arg, jurisdiction=jurisdiction_arg)
    if not rows:
        st.info("No incidents match the filters.")
    else:
        for inc in rows:
            with st.container():
                col1, col2, col3 = st.columns([3, 1, 1])
                with col1:
                    jur = inc.get("jurisdiction") or "—"
                    st.markdown(f"**{inc['title']}** — {inc['incident_type']} · {inc['severity']} · {inc['status']} · **{jur}**")
                    if inc.get("description"):
                        st.caption(inc["description"][:200] + ("..." if len(inc.get("description", "")) > 200 else ""))
                    flagged = escalation.get_flagged_for(inc)
                    if flagged:
                        st.caption("**Flagged for:** " + ", ".join(flagged))
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
                with st.expander("View / Edit formal report", expanded=False):
                    existing = (inc.get("formal_report") or "").strip()
                    if existing:
                        edited = st.text_area("Edit report", value=existing, height=200, key=f"report_edit_{inc['id']}")
                        if st.button("Save report", key=f"save_report_{inc['id']}"):
                            incidents.update_incident_formal_report(inc["id"], edited)
                            st.success("Report saved.")
                            st.rerun()
                    else:
                        if ai_incident.is_ai_configured():
                            if st.button("Generate formal report", key=f"gen_report_{inc['id']}"):
                                with st.spinner("Generating..."):
                                    mitigating = _get_decision_tree_recommendations(inc.get("incident_type") or "", inc.get("severity") or "")
                                    flagged = list(escalation.get_flagged_for(inc))
                                    report_text = ai_incident.generate_formal_report(
                                        inc,
                                        mitigating_actions=mitigating if mitigating else None,
                                        flagged_for=flagged if flagged else None,
                                    )
                                if report_text:
                                    incidents.update_incident_formal_report(inc["id"], report_text)
                                    st.success("Report generated. You can edit it above.")
                                    st.rerun()
                                else:
                                    st.error("Generation failed; please try again.")
                        else:
                            st.caption("Set ANTHROPIC_API_KEY or OPENAI_API_KEY to generate a formal report.")
                st.markdown("---")

    # Advanced manual form at the bottom so the one-step summary is always the first form
    st.markdown("---")
    with st.expander("Advanced — Log manually", expanded=False):
        st.caption("Use this form when you need to set type, severity, and title yourself.")
        with st.form("new_incident_manual"):
            title = st.text_input("Title *", placeholder="Short description of the incident", key="man_title")
            description = st.text_area("Description", placeholder="What happened? When? Where?", key="man_desc")
            col1, col2, col3 = st.columns(3)
            with col1:
                incident_type = st.selectbox("Incident type *", INCIDENT_TYPES, key="man_type")
            with col2:
                severity = st.selectbox("Severity *", SEVERITIES, key="man_sev")
            with col3:
                jurisdiction = st.selectbox("Jurisdiction *", JURISDICTIONS, key="man_jurisdiction")
            if st.form_submit_button("Submit incident"):
                if not title or not incident_type or not severity or not jurisdiction:
                    st.warning("Please fill in title, type, severity, and jurisdiction.")
                else:
                    incident_id = incidents.create_incident(
                        title=title,
                        description=description,
                        incident_type=incident_type,
                        severity=severity,
                        reported_by=reported_by,
                        reported_by_email=reported_by_email,
                        jurisdiction=jurisdiction,
                    )
                    inc_dict = {"title": title, "description": description, "incident_type": incident_type, "severity": severity, "jurisdiction": jurisdiction, "reported_at": ""}
                    flagged = list(escalation.get_flagged_for(inc_dict))
                    if ai_incident.is_ai_configured():
                        mitigating = _get_decision_tree_recommendations(incident_type, severity)
                        with st.spinner("Generating formal report..."):
                            report_text = ai_incident.generate_formal_report(
                                inc_dict,
                                mitigating_actions=mitigating if mitigating else None,
                                flagged_for=flagged if flagged else None,
                            )
                        if report_text:
                            incidents.update_incident_formal_report(incident_id, report_text)
                    st.success("Incident logged. **Flagged for:** " + ", ".join(flagged) if flagged else "Incident logged.")
                    st.rerun()


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
    st.markdown(tree.get("description", "Reference: type, severity, and recommended actions from the decision tree."))
    st.caption("Or just use **Log incident** on the Incident log page; AI will classify using this same framework.")
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
        flagged = escalation.get_flagged_for(r)
        display.append({
            "ID": r.get("id"),
            "Title": r.get("title"),
            "Type": r.get("incident_type"),
            "Severity": r.get("severity"),
            "Jurisdiction": r.get("jurisdiction") or "",
            "Status": r.get("status"),
            "Flagged for": ", ".join(flagged) if flagged else "",
            "Reported by": r.get("reported_by") or r.get("reported_by_email"),
            "Reported at": (r.get("reported_at") or "")[:10],
        })
    st.dataframe(display, use_container_width=True, hide_index=True)

    # Export CSV
    st.markdown("---")
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=["ID", "Title", "Type", "Severity", "Jurisdiction", "Status", "Flagged for", "Reported by", "Reported at"])
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
        # #region agent log
        _debug_log("app.py:show_dashboard", "Rendering Incident log page", {"page": page}, "H1")
        # #endregion
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
