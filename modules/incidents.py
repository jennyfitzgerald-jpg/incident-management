"""
Incident storage and retrieval. SQLite-backed for simplicity.
"""

import sqlite3
from pathlib import Path
from datetime import datetime
from typing import Optional

DB_DIR = Path(__file__).resolve().parent.parent / "database"
DB_PATH = DB_DIR / "incidents.db"


def _get_conn():
    DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create incidents table if it does not exist; add formal_report column if missing."""
    conn = _get_conn()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                incident_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                jurisdiction TEXT,
                reported_by TEXT,
                reported_by_email TEXT,
                reported_at TEXT NOT NULL,
                updated_at TEXT,
                resolution_notes TEXT,
                formal_report TEXT
            )
        """)
        conn.commit()
        for col in ("formal_report", "jurisdiction"):
            try:
                conn.execute(f"ALTER TABLE incidents ADD COLUMN {col} TEXT")
                conn.commit()
            except sqlite3.OperationalError:
                pass
    finally:
        conn.close()


def create_incident(
    title: str,
    description: str,
    incident_type: str,
    severity: str,
    reported_by: str = "",
    reported_by_email: str = "",
    jurisdiction: str = "",
) -> int:
    """Insert a new incident. Returns the new id."""
    init_db()
    now = datetime.utcnow().isoformat() + "Z"
    conn = _get_conn()
    try:
        cur = conn.execute(
            """
            INSERT INTO incidents (title, description, incident_type, severity, status, jurisdiction, reported_by, reported_by_email, reported_at, updated_at)
            VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?, ?)
            """,
            (title, description, incident_type, severity, jurisdiction or "", reported_by, reported_by_email, now, now),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def list_incidents(
    status: Optional[str] = None,
    incident_type: Optional[str] = None,
    severity: Optional[str] = None,
    jurisdiction: Optional[str] = None,
    limit: int = 500,
) -> list[dict]:
    """Return incidents as list of dicts, optional filters."""
    init_db()
    conn = _get_conn()
    try:
        q = "SELECT * FROM incidents WHERE 1=1"
        params = []
        if status:
            q += " AND status = ?"
            params.append(status)
        if incident_type:
            q += " AND incident_type = ?"
            params.append(incident_type)
        if severity:
            q += " AND severity = ?"
            params.append(severity)
        if jurisdiction:
            q += " AND jurisdiction = ?"
            params.append(jurisdiction)
        q += " ORDER BY reported_at DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(q, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def update_incident_status(incident_id: int, status: str, resolution_notes: str = "") -> bool:
    """Update status and optionally resolution notes. Returns True if a row was updated."""
    now = datetime.utcnow().isoformat() + "Z"
    conn = _get_conn()
    try:
        cur = conn.execute(
            "UPDATE incidents SET status = ?, resolution_notes = ?, updated_at = ? WHERE id = ?",
            (status, resolution_notes or "", now, incident_id),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def get_incident(incident_id: int) -> Optional[dict]:
    """Return one incident by id or None."""
    init_db()
    conn = _get_conn()
    try:
        row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def update_incident_formal_report(incident_id: int, formal_report: str) -> bool:
    """Update the formal report for an incident. Returns True if a row was updated."""
    conn = _get_conn()
    try:
        cur = conn.execute(
            "UPDATE incidents SET formal_report = ?, updated_at = ? WHERE id = ?",
            (formal_report, datetime.utcnow().isoformat() + "Z", incident_id),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()
