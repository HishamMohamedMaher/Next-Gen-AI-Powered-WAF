"""SQLite persistence layer and connection manager for AI-WAF.

Manages dedicated read and write SQLite database connections, WAL mode concurrency,
schema definitions, batch insertion of WAF audit events, security alerts,
dynamic blacklist persistence, and threat intelligence cache records.
"""

from __future__ import annotations

import datetime
import logging
import os
import sqlite3
from typing import Any, Dict, List, Optional

from waf.models import Alert, WAFEvent

logger = logging.getLogger(__name__)

DB_PATH: str = "data/waf.db"

_write_conn: Optional[sqlite3.Connection] = None
_read_conn: Optional[sqlite3.Connection] = None

SCHEMA_WAF_EVENTS: str = """
CREATE TABLE IF NOT EXISTS waf_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    payload_snippet TEXT,
    attack_type TEXT,
    layer TEXT,
    rule_id TEXT,
    confidence REAL DEFAULT 0.0,
    action TEXT NOT NULL,
    processing_time_ms REAL DEFAULT 0.0,
    country TEXT,
    latitude REAL,
    longitude REAL
);

CREATE INDEX IF NOT EXISTS idx_waf_events_timestamp ON waf_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_waf_events_client_ip ON waf_events(client_ip);
CREATE INDEX IF NOT EXISTS idx_waf_events_attack_type ON waf_events(attack_type);
CREATE INDEX IF NOT EXISTS idx_waf_events_action ON waf_events(action);
"""

SCHEMA_ALERTS: str = """
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    severity TEXT NOT NULL,
    attack_type TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    path TEXT NOT NULL,
    payload_snippet TEXT,
    confidence REAL DEFAULT 0.0,
    count INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'open',
    rule_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_client_ip ON alerts(client_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_attack_type ON alerts(attack_type);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
"""

SCHEMA_BLACKLIST: str = """
CREATE TABLE IF NOT EXISTS blacklist (
    ip TEXT PRIMARY KEY,
    reason TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_blacklist_expires_at ON blacklist(expires_at);
"""

SCHEMA_ABUSEIPDB_CACHE: str = """
CREATE TABLE IF NOT EXISTS abuseipdb_cache (
    ip TEXT PRIMARY KEY,
    abuse_confidence_score INTEGER NOT NULL,
    raw_response TEXT NOT NULL,
    cached_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_abuseipdb_cache_cached_at ON abuseipdb_cache(cached_at);
"""


def init_db(db_path: str = DB_PATH) -> None:
    """Initialize SQLite database connections, enable WAL mode, and create tables with indexes."""
    global _write_conn, _read_conn

    # Ensure parent directory exists
    dir_name = os.path.dirname(db_path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)

    # Initialize write connection and enable WAL
    _write_conn = sqlite3.connect(db_path, check_same_thread=False)
    _write_conn.row_factory = sqlite3.Row

    _write_conn.execute("PRAGMA journal_mode=WAL;")
    _write_conn.execute("PRAGMA busy_timeout=5000;")

    # Execute Schemas
    cursor = _write_conn.cursor()
    cursor.executescript(SCHEMA_WAF_EVENTS)
    cursor.executescript(SCHEMA_ALERTS)
    cursor.executescript(SCHEMA_BLACKLIST)
    cursor.executescript(SCHEMA_ABUSEIPDB_CACHE)
    _write_conn.commit()

    # Initialize dedicated read-only connection
    _read_conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, check_same_thread=False)
    _read_conn.row_factory = sqlite3.Row
    _read_conn.execute("PRAGMA busy_timeout=5000;")

    logger.info(f"Database initialized successfully at {db_path} with WAL mode.")


def close_db() -> None:
    """Safely commit pending transactions and close both read and write connections."""
    global _write_conn, _read_conn

    if _write_conn:
        _write_conn.commit()
        _write_conn.close()
        _write_conn = None

    if _read_conn:
        _read_conn.close()
        _read_conn = None

    logger.info("Database connections closed cleanly.")


def insert_batch(events: List[WAFEvent]) -> None:
    """Insert a batch of WAFEvent objects into waf_events in a single transaction."""
    global _write_conn
    if not _write_conn or not events:
        return

    query = """
    INSERT INTO waf_events (
        request_id, timestamp, client_ip, method, path, payload_snippet,
        attack_type, layer, rule_id, confidence, action, processing_time_ms,
        country, latitude, longitude
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    data = [
        (
            e.request_id,
            str(e.timestamp),
            e.client_ip,
            e.method,
            e.path,
            e.payload_snippet,
            e.attack_type.value if hasattr(e.attack_type, 'value') else str(e.attack_type),
            e.layer.value if hasattr(e.layer, 'value') else str(e.layer),
            e.rule_id,
            e.confidence,
            e.action.value if hasattr(e.action, 'value') else str(e.action),
            e.processing_time_ms,
            e.country,
            e.latitude,
            e.longitude,
        )
        for e in events
    ]

    cursor = _write_conn.cursor()
    cursor.executemany(query, data)
    _write_conn.commit()


def insert_alert(alert: Alert) -> None:
    """Persist a new security alert record or upsert count and last_seen on duplicate."""
    global _write_conn
    if not _write_conn:
        return

    query = """
    INSERT INTO alerts (
        id, created_at, last_seen, severity, attack_type, client_ip,
        path, payload_snippet, confidence, count, status, rule_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
        last_seen = excluded.last_seen,
        count = alerts.count + 1;
    """

    cursor = _write_conn.cursor()
    cursor.execute(
        query,
        (
            alert.id,
            str(alert.created_at),
            str(alert.last_seen),
            alert.severity,
            alert.attack_type.value if hasattr(alert.attack_type, 'value') else str(alert.attack_type),
            alert.client_ip,
            alert.path,
            alert.payload_snippet,
            alert.confidence,
            alert.count,
            alert.status,
            alert.rule_id,
        ),
    )
    _write_conn.commit()


def update_alert_status(alert_id: str, status: str) -> None:
    """Update resolution status of a security alert."""
    global _write_conn
    if not _write_conn:
        return

    query = "UPDATE alerts SET status = ? WHERE id = ?"
    cursor = _write_conn.cursor()
    cursor.execute(query, (status, alert_id))
    _write_conn.commit()


def get_blacklist_entries() -> List[Dict[str, Any]]:
    """Retrieve all active blacklist records from SQLite."""
    global _read_conn
    if not _read_conn:
        return []

    cursor = _read_conn.cursor()
    cursor.execute("SELECT ip, reason, created_at, expires_at FROM blacklist")
    rows = cursor.fetchall()

    return [dict(row) for row in rows]


def cache_abuseipdb(ip: str, score: int, raw_response: str) -> None:
    """Store or update AbuseIPDB query response in the local cache table."""
    global _write_conn
    if not _write_conn:
        return

    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    query = """
    INSERT INTO abuseipdb_cache (ip, abuse_confidence_score, raw_response, cached_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(ip) DO UPDATE SET
        abuse_confidence_score = excluded.abuse_confidence_score,
        raw_response = excluded.raw_response,
        cached_at = excluded.cached_at;
    """

    cursor = _write_conn.cursor()
    cursor.execute(query, (ip, score, raw_response, now))
    _write_conn.commit()


def get_abuseipdb_cache(ip: str, max_age_hours: int = 24) -> Optional[Dict[str, Any]]:
    """Fetch cached AbuseIPDB result if it exists and has not exceeded max_age_hours."""
    global _read_conn
    if not _read_conn:
        return None

    cursor = _read_conn.cursor()
    cursor.execute(
        "SELECT ip, abuse_confidence_score, raw_response, cached_at FROM abuseipdb_cache WHERE ip = ?",
        (ip,),
    )
    row = cursor.fetchone()

    if not row:
        return None

    record = dict(row)
    cached_time = datetime.datetime.fromisoformat(record["cached_at"])
    if cached_time.tzinfo is None:
        cached_time = cached_time.replace(tzinfo=datetime.timezone.utc)

    now = datetime.datetime.now(datetime.timezone.utc)
    if now - cached_time > datetime.timedelta(hours=max_age_hours):
        return None

    return record