"""
Secure server-side store for OAuth state, PKCE, one-time codes, and rate limiting.
Uses SQLite so no Redis dependency; survives redirects and multi-worker.
"""

import sqlite3
import time
import secrets
from pathlib import Path
from typing import Optional, Dict, Any
from contextlib import contextmanager

# Default store path (relative to project root)
DEFAULT_STORE_PATH = Path(__file__).parent.parent / "database" / "auth_store.db"
OAUTH_PENDING_TTL_SECONDS = 600  # 10 minutes
FIREBASE_CODE_TTL_SECONDS = 120  # 2 minutes
RATE_LIMIT_WINDOW_SECONDS = 300  # 5 minutes
RATE_LIMIT_MAX_ATTEMPTS = 10


def _get_connection(store_path: Path) -> sqlite3.Connection:
    store_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(store_path), timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_store(store_path: Path = DEFAULT_STORE_PATH) -> None:
    """Create tables if they do not exist."""
    conn = _get_connection(store_path)
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS oauth_pending (
                state TEXT PRIMARY KEY,
                code_verifier TEXT NOT NULL,
                nonce TEXT,
                redirect_uri TEXT,
                created_at REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS firebase_code_exchange (
                code TEXT PRIMARY KEY,
                payload_encrypted TEXT NOT NULL,
                created_at REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS rate_limit (
                key TEXT NOT NULL,
                window_start REAL NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (key, window_start)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_oauth_pending_created ON oauth_pending(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_firebase_code_created ON firebase_code_exchange(created_at)")
        conn.commit()
    finally:
        conn.close()


@contextmanager
def _conn(store_path: Path = DEFAULT_STORE_PATH):
    conn = _get_connection(store_path)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def _prune_oauth_pending(conn: sqlite3.Connection, store_path: Path) -> None:
    cutoff = time.time() - OAUTH_PENDING_TTL_SECONDS
    conn.execute("DELETE FROM oauth_pending WHERE created_at < ?", (cutoff,))


def save_oauth_pending(
    state: str,
    code_verifier: str,
    nonce: Optional[str] = None,
    redirect_uri: Optional[str] = None,
    store_path: Path = DEFAULT_STORE_PATH,
) -> None:
    init_store(store_path)
    with _conn(store_path) as conn:
        _prune_oauth_pending(conn, store_path)
        conn.execute(
            "INSERT OR REPLACE INTO oauth_pending (state, code_verifier, nonce, redirect_uri, created_at) VALUES (?, ?, ?, ?, ?)",
            (state, code_verifier, nonce or "", redirect_uri or "", time.time()),
        )


def consume_oauth_pending(
    state: str,
    store_path: Path = DEFAULT_STORE_PATH,
) -> Optional[Dict[str, Any]]:
    """Return and delete the pending row for state. Returns None if missing or expired."""
    init_store(store_path)
    with _conn(store_path) as conn:
        _prune_oauth_pending(conn, store_path)
        row = conn.execute(
            "SELECT code_verifier, nonce, redirect_uri FROM oauth_pending WHERE state = ?",
            (state,),
        ).fetchone()
        if not row:
            return None
        conn.execute("DELETE FROM oauth_pending WHERE state = ?", (state,))
        return {
            "code_verifier": row["code_verifier"],
            "nonce": row["nonce"] or None,
            "redirect_uri": row["redirect_uri"] or None,
        }


def save_firebase_code(payload_encrypted: str, store_path: Path = DEFAULT_STORE_PATH) -> str:
    """Store encrypted payload under a one-time code; return the code."""
    init_store(store_path)
    code = secrets.token_urlsafe(32)
    with _conn(store_path) as conn:
        conn.execute(
            "INSERT INTO firebase_code_exchange (code, payload_encrypted, created_at) VALUES (?, ?, ?)",
            (code, payload_encrypted, time.time()),
        )
    return code


def consume_firebase_code(code: str, store_path: Path = DEFAULT_STORE_PATH) -> Optional[str]:
    """Return encrypted payload and delete the row. None if missing or expired."""
    init_store(store_path)
    cutoff = time.time() - FIREBASE_CODE_TTL_SECONDS
    with _conn(store_path) as conn:
        conn.execute("DELETE FROM firebase_code_exchange WHERE created_at < ?", (cutoff,))
        row = conn.execute(
            "SELECT payload_encrypted FROM firebase_code_exchange WHERE code = ?",
            (code,),
        ).fetchone()
        if not row:
            return None
        conn.execute("DELETE FROM firebase_code_exchange WHERE code = ?", (code,))
        return row["payload_encrypted"]


def check_rate_limit(key: str, store_path: Path = DEFAULT_STORE_PATH) -> bool:
    """Return True if allowed, False if rate limited."""
    init_store(store_path)
    now = time.time()
    window_start = now - (now % RATE_LIMIT_WINDOW_SECONDS)
    with _conn(store_path) as conn:
        row = conn.execute(
            "SELECT attempts FROM rate_limit WHERE key = ? AND window_start = ?",
            (key, window_start),
        ).fetchone()
        if not row:
            conn.execute(
                "INSERT INTO rate_limit (key, window_start, attempts) VALUES (?, ?, 1)",
                (key, window_start),
            )
            return True
        attempts = row["attempts"] + 1
        if attempts > RATE_LIMIT_MAX_ATTEMPTS:
            return False
        conn.execute(
            "UPDATE rate_limit SET attempts = ? WHERE key = ? AND window_start = ?",
            (attempts, key, window_start),
        )
        return True


def clear_rate_limit(key: str, store_path: Path = DEFAULT_STORE_PATH) -> None:
    """Clear rate limit for key (e.g. after successful login)."""
    init_store(store_path)
    with _conn(store_path) as conn:
        conn.execute("DELETE FROM rate_limit WHERE key = ?", (key,))
