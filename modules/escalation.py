"""
Escalation: who needs to be aware for a given incident.
Loaded from config/escalation.json (edit to add users).
"""

import json
from pathlib import Path
from typing import List, Dict, Any

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "escalation.json"

# Severities that trigger high_risk (CMO etc.)
HIGH_RISK_SEVERITIES = ("High", "Critical")


def _load_config() -> Dict[str, Any]:
    if not CONFIG_PATH.exists():
        return {}
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def get_flagged_for(incident: Dict[str, Any]) -> List[str]:
    """
    Return a list of short strings describing who needs to be aware for this incident.
    incident must have at least: severity, jurisdiction (optional).
    """
    cfg = _load_config()
    out = []

    # All incidents: quality, information security, data protection
    for item in cfg.get("all_incidents", []):
        role = item.get("role", "")
        name = item.get("name", "")
        if name:
            out.append(f"{name} ({role})" if role else name)

    # High risk: CMO
    severity = (incident.get("severity") or "").strip()
    if severity in HIGH_RISK_SEVERITIES:
        for item in cfg.get("high_risk", []):
            role = item.get("role", "")
            name = item.get("name", "")
            if name:
                out.append(f"{name} ({role})" if role else name)

    # Jurisdiction: UK or US lab team
    jurisdiction = (incident.get("jurisdiction") or "").strip().upper()
    if jurisdiction:
        teams = cfg.get("jurisdiction_teams", {}).get(jurisdiction, [])
        for team in teams:
            label = team.get("label", "")
            email = team.get("email", "")
            if label and email:
                out.append(f"{label} ({email})")
            elif email:
                out.append(email)

    return out


def get_jurisdictions() -> List[str]:
    """Return list of jurisdiction codes from config (e.g. UK, US)."""
    cfg = _load_config()
    teams = cfg.get("jurisdiction_teams", {})
    return list(teams.keys()) if teams else ["UK", "US"]
