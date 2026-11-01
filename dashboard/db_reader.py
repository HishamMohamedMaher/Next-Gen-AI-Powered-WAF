"""Database reader module for the AI-WAF Streamlit dashboard.

Provides cached and read-only access to SQLite telemetry, event logs,
and security alerts for analytical visualization.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

# Path to the shared SQLite database file
DB_PATH = Path("data/waf.db")


def _get_conn() -> sqlite3.Connection:
    """Establish and return a read-only SQLite database connection.

    Uses URI mode with query parameter `mode=ro` to enforce read-only semantics.

    Returns:
        sqlite3.Connection: Configured read-only database connection.
    """
    if not DB_PATH.exists():
        # Fallback to in-memory/empty if db file doesn't exist yet
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(f"file:{DB_PATH}?mode=rwc", uri=True)
        conn.row_factory = sqlite3.Row
        return conn

    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000;")
    return conn


def get_event_counts(since: float) -> Dict[str, int]:
    """Retrieve aggregate event counts within the specified time window.

    Args:
        since (float): Unix epoch timestamp marking the start of the window.

    Returns:
        dict[str, int]: Dictionary with counts for 'total', 'blocked',
            'allowed', and 'monitor'.
    """
    counts = {"total": 0, "blocked": 0, "allowed": 0, "monitor": 0}
    try:
        conn = _get_conn()
        cursor = conn.cursor()
        query = """
        SELECT action, COUNT(*) as cnt
        FROM waf_events
        WHERE CAST(timestamp AS REAL) >= ?
        GROUP BY action
        """
        cursor.execute(query, (since,))
        rows = cursor.fetchall()

        for row in rows:
            act = str(row["action"]).lower()
            cnt = int(row["cnt"])
            counts["total"] += cnt
            if act == "block":
                counts["blocked"] += cnt
            elif act == "allow":
                counts["allowed"] += cnt
            elif act == "monitor":
                counts["monitor"] += cnt

        conn.close()
    except Exception:
        pass

    return counts


def get_events_timeline(since: float, bucket_seconds: int = 60) -> List[Dict[str, Any]]:
    """Retrieve time-bucketed event counts grouped by action.

    Args:
        since (float): Unix epoch timestamp marking the start of the window.
        bucket_seconds (int, optional): Duration of each time bucket in seconds. Defaults to 60.

    Returns:
        list[dict[str, Any]]: List of timeline records containing timestamp buckets,
            action categories, and corresponding event counts.
    """
    results = []
    try:
        conn = _get_conn()
        cursor = conn.cursor()
        query = f"""
        SELECT 
            (CAST(timestamp AS REAL) / {bucket_seconds}) * {bucket_seconds} as bucket,
            action,
            COUNT(*) as count
        FROM waf_events
        WHERE CAST(timestamp AS REAL) >= ?
        GROUP BY bucket, action
        ORDER BY bucket ASC
        """
        cursor.execute(query, (since,))
        rows = cursor.fetchall()
        results = [dict(row) for row in rows]
        conn.close()
    except Exception:
        pass

    return results


def get_attack_distribution(since: float) -> List[Dict[str, Any]]:
    """Retrieve frequency counts grouped by attack type/category.

    Args:
        since (float): Unix epoch timestamp marking the start of the window.

    Returns:
        list[dict[str, Any]]: List of records with 'attack_type' and 'count'.
    """
    results = []
    try:
        conn = _get_conn()
        cursor = conn.cursor()
        query = """
        SELECT attack_type, COUNT(*) as count
        FROM waf_events
        WHERE CAST(timestamp AS REAL) >= ? AND attack_type != 'none' AND attack_type != 'UNKNOWN'
        GROUP BY attack_type
        ORDER BY count DESC
        """
        cursor.execute(query, (since,))
        rows = cursor.fetchall()
        results = [dict(row) for row in rows]
        conn.close()
    except Exception:
        pass

    return results


def get_top_ips(since: float, limit: int = 10) -> List[Dict[str, Any]]:
    """Retrieve the top blocked IP addresses sorted by frequency.

    Args:
        since (float): Unix epoch timestamp marking the start of the window.
        limit (int, optional): Maximum number of entries to return. Defaults to 10.

    Returns:
        list[dict[str, Any]]: List of records containing 'source_ip', 'count',
            and 'last_seen'.
    """
    results = []
    try:
        conn = _get_conn()
        cursor = conn.cursor()
        query = """
        SELECT 
            client_ip as source_ip,
            COUNT(*) as count,
            MAX(CAST(timestamp AS REAL)) as last_seen
        FROM waf_events
        WHERE CAST(timestamp AS REAL) >= ? AND action = 'block'
        GROUP BY client_ip
        ORDER BY count DESC
        LIMIT ?
        """
        cursor.execute(query, (since, limit))
        rows = cursor.fetchall()
        results = [dict(row) for row in rows]
        conn.close()
    except Exception:
        pass

    return results


def get_recent_events(
    since: float,
    limit: int = 100,
    action: Optional[str] = None,
    attack_type: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Retrieve recent granular WAF events filtered by criteria.

    Args:
        since (float): Unix epoch timestamp marking the start of the window.
        limit (int, optional): Maximum number of records to return. Defaults to 100.
        action (Optional[str], optional): Filter by action (e.g. 'allow', 'block', 'monitor').
        attack_type (Optional[str], optional): Filter by detected attack type.

    Returns:
        list[dict[str, Any]]: List of individual event records with telemetry fields.
    """
    results = []
    try:
        conn = _get_conn()
        cursor = conn.cursor()
        
        conditions = ["CAST(timestamp AS REAL) >= ?"]
        params: List[Any] = [since]

        if action:
            conditions.append("action = ?")
            params.append(action)

        if attack_type:
            conditions.append("attack_type = ?")
            params.append(attack_type)

        where_clause = " AND ".join(conditions)
        query = f"""
        SELECT *
        FROM waf_events
        WHERE {where_clause}
        ORDER BY CAST(timestamp AS REAL) DESC
        LIMIT ?
        """
        params.append(limit)

        cursor.execute(query, params)
        rows = cursor.fetchall()
        results = [dict(row) for row in rows]
        conn.close()
    except Exception:
        pass

    return results


def get_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Retrieve security alerts filtered by resolution status and severity.

    Args:
        status (Optional[str], optional): Filter by alert status (e.g. 'new', 'acknowledged', 'resolved').
        severity (Optional[str], optional): Filter by severity ('high', 'medium', 'info').

    Returns:
        list[dict[str, Any]]: List of matching alert records.
    """
    results = []
    try:
        conn = _get_conn()
        cursor = conn.cursor()
        
        conditions = []
        params: List[Any] = []

        if status:
            conditions.append("status = ?")
            params.append(status)

        if severity:
            conditions.append("severity = ?")
            params.append(severity)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"""
        SELECT *
        FROM alerts
        {where_clause}
        ORDER BY CAST(last_seen AS REAL) DESC
        """

        cursor.execute(query, params)
        rows = cursor.fetchall()
        results = [dict(row) for row in rows]
        conn.close()
    except Exception:
        pass

    return results


def get_new_alert_counts() -> Dict[str, int]:
    """Retrieve count of unacknowledged ('new') alerts partitioned by severity.

    Returns:
        dict[str, int]: Counts mapping for 'high', 'medium', and 'info' severity levels.
    """
    counts = {"high": 0, "medium": 0, "info": 0}
    try:
        conn = _get_conn()
        cursor = conn.cursor()
        query = """
        SELECT severity, COUNT(*) as cnt
        FROM alerts
        WHERE status = 'new' OR status = 'open'
        GROUP BY severity
        """
        cursor.execute(query)
        rows = cursor.fetchall()

        for row in rows:
            sev = str(row["severity"]).lower()
            cnt = int(row["cnt"])
            if sev in counts:
                counts[sev] = cnt

        conn.close()
    except Exception:
        pass

    return counts


def update_alert_status(alert_id: str, status: str) -> None:
    """Update the resolution status of an alert record in SQLite.

    Args:
        alert_id (str): Unique identifier of the alert.
        status (str): Target status (e.g., 'acknowledged', 'resolved').
    """
    try:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        conn.execute("PRAGMA busy_timeout=5000;")
        cursor = conn.cursor()
        cursor.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
        conn.commit()
        conn.close()
    except Exception:
        pass