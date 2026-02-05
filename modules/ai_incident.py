"""
AI-powered incident parsing and formal report generation.
Supports Anthropic Claude or OpenAI; either API key enables the agentic flow.
"""

import json
import os
import logging
import time
from pathlib import Path
from typing import Optional, Tuple, List

logger = logging.getLogger(__name__)

# Last error from _call_llm (set on API exception, cleared on success) — for user-facing message
_last_llm_error: Optional[str] = None

# #region agent log
def _agent_log(location: str, message: str, data: dict = None):
    try:
        log_path = Path(__file__).resolve().parent.parent / ".cursor" / "debug.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"location": location, "message": message, "timestamp": int(time.time() * 1000)}
        if data:
            payload["data"] = data
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload) + "\n")
    except Exception:
        pass
# #endregion

# Exact labels used in app.py for incident_type and severity (must match decision tree)
INCIDENT_TYPE_LABELS = [
    "Specimen / sample",
    "Imaging / slide quality",
    "Workflow / process",
    "Equipment / system",
    "Safety / compliance",
    "Other",
]
SEVERITY_LABELS = ["Low", "Medium", "High", "Critical"]

# Domain context for Diagnexia (outsourced pathology) — used in parse and report prompts
DIAGNEXIA_CONTEXT = """Context: Diagnexia is an outsourced digital pathology provider. We receive slides/specimens from client sites, process and scan them, and deliver results. Severity should reflect impact on turnaround time (TAT), patient/sample safety, and need for recuts or re-sends from the client.
Examples: Broken or damaged slides in transit → Specimen / sample, Medium severity (TAT compromised; recuts from client site required). Mislabeled slide → Specimen / sample, Medium or High depending on whether it was caught before reporting. Equipment failure delaying scans → Equipment / system, severity by impact on TAT and workload."""


def _get_secret(key: str) -> str:
    """Get key from env or st.secrets."""
    val = os.getenv(key, "")
    if val:
        return val
    try:
        import streamlit as st
        if hasattr(st, "secrets") and st.secrets and key in st.secrets:
            return str(st.secrets.get(key, ""))
    except Exception:
        pass
    return ""


def _get_anthropic_key() -> str:
    return _get_secret("ANTHROPIC_API_KEY")


def _get_openai_key() -> str:
    return _get_secret("OPENAI_API_KEY")


def is_ai_configured() -> bool:
    """True if either ANTHROPIC_API_KEY or OPENAI_API_KEY is set."""
    ak = _get_anthropic_key()
    ok = _get_openai_key()
    configured = bool(ak) or bool(ok)
    # #region agent log
    _agent_log("ai_incident.is_ai_configured", "check", {"configured": configured, "has_anthropic": bool(ak), "has_openai": bool(ok)})
    # #endregion
    return configured


def get_ai_status() -> str:
    """Return a short label for UI: 'Anthropic', 'OpenAI', or 'Not configured'."""
    if _get_anthropic_key():
        return "Anthropic"
    if _get_openai_key():
        return "OpenAI"
    return "Not configured"


def _call_llm(prompt: str, max_tokens: int = 1024) -> Optional[str]:
    """
    Call LLM with the given prompt. Uses Anthropic if ANTHROPIC_API_KEY is set,
    else OpenAI if OPENAI_API_KEY is set. Returns response text or None.
    On failure, sets _last_llm_error for user-facing diagnostics.
    """
    global _last_llm_error
    _last_llm_error = None
    anthropic_key = _get_anthropic_key()
    openai_key = _get_openai_key()
    # #region agent log
    _agent_log("ai_incident._call_llm", "entry", {"has_anthropic": bool(anthropic_key), "has_openai": bool(openai_key), "prompt_len": len(prompt)})
    # #endregion
    if anthropic_key:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=anthropic_key)
            msg = client.messages.create(
                model="claude-3-5-haiku-20241022",
                max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )
            text = msg.content[0].text if msg.content else ""
            return text.strip() if text else None
        except Exception as e:
            logger.warning("Anthropic API call failed: %s", e)
            _last_llm_error = str(e)
            # #region agent log
            _agent_log("ai_incident._call_llm", "anthropic_error", {"error": str(e)})
            # #endregion
            return None
    if openai_key:
        try:
            from openai import OpenAI
            client = OpenAI(api_key=openai_key)
            r = client.chat.completions.create(
                model="gpt-4o-mini",
                max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )
            text = (r.choices[0].message.content or "").strip()
            return text if text else None
        except Exception as e:
            logger.warning("OpenAI API call failed: %s", e)
            _last_llm_error = str(e)
            # #region agent log
            _agent_log("ai_incident._call_llm", "openai_error", {"error": str(e)})
            # #endregion
            return None
    # #region agent log
    _agent_log("ai_incident._call_llm", "no_provider", {})
    # #endregion
    return None


def parse_incident_description(free_text: str) -> Optional[dict]:
    """
    Use LLM to extract title, incident_type, severity, description from free text.
    Returns a dict with keys title, incident_type, severity, description, jurisdiction (optional),
    or None on failure. Uses _call_llm so works with either Anthropic or OpenAI.
    """
    if not is_ai_configured() or not free_text or not free_text.strip():
        return None

    types_str = ", ".join(repr(s) for s in INCIDENT_TYPE_LABELS)
    severities_str = ", ".join(repr(s) for s in SEVERITY_LABELS)
    prompt = f"""You are helping to log an incident for Diagnexia (an outsourced digital pathology provider). The user has provided a short description. Extract structured fields and assign severity based on impact on turnaround time, patient/sample safety, and need for recuts or re-sends from the client.

{DIAGNEXIA_CONTEXT}

Allowed incident_type (use exactly one): {types_str}
Allowed severity (use exactly one): {severities_str}

Return a single JSON object with exactly these keys (no other keys):
- "title": short, clear title (one line)
- "incident_type": one of the allowed incident_type values above, exactly as written
- "severity": one of the allowed severity values above, exactly as written
- "description": cleaned-up version of the user's description, or the original if already clear (may be multiple sentences)
- "jurisdiction": "UK" or "US" only if clearly stated or implied (e.g. UK lab, US site, London, New York); otherwise ""

User description:
---
{free_text.strip()}
---

Output ONLY the raw JSON object. No markdown, no code fences, no text before or after."""

    text = _call_llm(prompt)
    if not text:
        text = _call_llm(prompt)  # Retry once on transient failure
    if not text:
        return None
    text = text.strip()
    # Strip markdown code block if present
    if text.startswith("```"):
        lines = text.split("\n")
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines)
    # Extract JSON object if model added text around it (e.g. "Here is the result: {...}")
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        text = text[start : end + 1]
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    title = data.get("title") or ""
    incident_type = data.get("incident_type") or ""
    severity = data.get("severity") or ""
    description = data.get("description") or free_text.strip()
    if incident_type not in INCIDENT_TYPE_LABELS:
        incident_type = INCIDENT_TYPE_LABELS[-1]
    if severity not in SEVERITY_LABELS:
        severity = SEVERITY_LABELS[0]
    if not title:
        title = free_text[:80] + ("..." if len(free_text) > 80 else "")
    jurisdiction = (data.get("jurisdiction") or "").strip().upper()
    if jurisdiction not in ("UK", "US"):
        jurisdiction = ""
    return {
        "title": title,
        "incident_type": incident_type,
        "severity": severity,
        "description": description,
        "jurisdiction": jurisdiction,
    }


def generate_formal_report(
    incident: dict,
    mitigating_actions: Optional[List[str]] = None,
    flagged_for: Optional[List[str]] = None,
) -> Optional[str]:
    """
    Generate a formal incident report with summary, root cause, and mitigating actions.
    mitigating_actions: list from decision tree for this type/severity (included in report).
    flagged_for: who has been flagged (escalation); optional line in report.
    """
    if not is_ai_configured():
        return None

    title = incident.get("title") or "Incident"
    description = incident.get("description") or ""
    incident_type = incident.get("incident_type") or ""
    severity = incident.get("severity") or ""
    reported_at = incident.get("reported_at") or ""
    jurisdiction = incident.get("jurisdiction") or ""

    actions_blob = ""
    if mitigating_actions:
        actions_blob = "Use these as the primary mitigating actions (include each, you may add brief context):\n" + "\n".join(f"- {a}" for a in mitigating_actions)
    else:
        actions_blob = "Suggest appropriate mitigating actions based on type and severity."

    escalation_blob = ""
    if flagged_for:
        escalation_blob = f"\nEscalation / who has been flagged: {', '.join(flagged_for)}. Include a short line in the report that these parties have been flagged."

    prompt = f"""Write a short formal incident report for Diagnexia (outsourced digital pathology provider). Use a professional tone. Consider impact on turnaround time, client recuts, and sample/slide integrity where relevant.

{DIAGNEXIA_CONTEXT}

Structure the report with these sections:

1. **Summary** – What happened, severity, type, and jurisdiction (1–2 sentences).
2. **Root cause** – Inferred from the description; 1–2 sentences.
3. **Mitigating actions** – {actions_blob}
4. Optionally a brief line on escalation if relevant. {escalation_blob}

Incident details:
- Title: {title}
- Type: {incident_type}
- Severity: {severity}
- Jurisdiction: {jurisdiction}
- Description: {description}
- Reported at: {reported_at}

Write the report text with clear paragraph breaks. Use the section headings Summary, Root cause, Mitigating actions (and Escalation if applicable)."""

    return _call_llm(prompt, max_tokens=1024)


def quick_log_incident(
    free_text: str,
    jurisdiction_fallback: str,
    reported_by: str = "",
    reported_by_email: str = "",
    create_incident_fn=None,
    update_report_fn=None,
    get_flagged_fn=None,
    get_recommendations_fn=None,
) -> Tuple[Optional[int], Optional[dict], Optional[str], List[str], Optional[str]]:
    """
    One-step agentic flow: parse → create incident → get recommendations → generate report (with root cause + mitigating actions) → save.
    get_recommendations_fn(incident_type_label, severity_label) -> list of strings (from decision tree).
    Returns (incident_id, inc_dict, report_text, flagged, error_message).
    """
    if not free_text or not free_text.strip():
        return (None, None, None, [], "Please enter a short description.")
    try:
        parsed = parse_incident_description(free_text)
    except Exception as e:
        logger.exception("parse_incident_description failed")
        return (None, None, None, [], f"AI parse failed: {str(e)}. Try again or use Advanced — Log manually.")
    if not parsed:
        detail = ""
        if _last_llm_error:
            detail = f" API error: {_last_llm_error}"
        return (None, None, None, [], f"AI could not parse the description.{detail} Check API key in Secrets or use Advanced — Log manually.")
    if not create_incident_fn:
        return (None, None, None, [], "Configuration error: create_incident not set.")
    jurisdiction = (parsed.get("jurisdiction") or "").strip() or (jurisdiction_fallback or "UK")
    try:
        incident_id = create_incident_fn(
            title=parsed.get("title", ""),
            description=parsed.get("description", ""),
            incident_type=parsed.get("incident_type", "Other"),
            severity=parsed.get("severity", "Low"),
            reported_by=reported_by,
            reported_by_email=reported_by_email,
            jurisdiction=jurisdiction,
        )
    except Exception as e:
        logger.exception("create_incident failed")
        return (None, parsed, None, [], f"Could not save incident: {str(e)}")
    if not incident_id:
        return (None, parsed, None, [], "Could not save incident (database returned no id).")
    incident_dict = {
        **parsed,
        "id": incident_id,
        "jurisdiction": jurisdiction,
        "reported_at": "",
    }
    flagged = list(get_flagged_fn(incident_dict)) if get_flagged_fn else []
    mitigating_actions = []
    if get_recommendations_fn:
        mitigating_actions = list(get_recommendations_fn(parsed.get("incident_type", ""), parsed.get("severity", "")) or [])
    report_text = None
    if update_report_fn:
        report_text = generate_formal_report(
            incident_dict,
            mitigating_actions=mitigating_actions if mitigating_actions else None,
            flagged_for=flagged if flagged else None,
        )
        if report_text:
            update_report_fn(incident_id, report_text)
    return (incident_id, incident_dict, report_text, flagged, None)
