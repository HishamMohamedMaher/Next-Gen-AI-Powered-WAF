"""Dynamic blacklist management module for AI-WAF.

Provides fast in-memory blacklist lookups, strike tracking with sliding
time windows, automatic escalation to temporary bans, and synchronization
with persistent storage in SQLite.
"""

from __future__ import annotations

import logging
from pathlib import Path
import sqlite3
import time
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# In-memory fast lookup set for active blacklisted IPs
_blacklist: Set[str] = set()

# Internal expiration mapping (IP -> expiration timestamp)
_expiry: Dict[str, float] = {}

# Strike tracker mapping IP address to timestamps of recent block events
_strikes: Dict[str, List[float]] = {}

# Default escalation configuration
DEFAULT_STRIKE_THRESHOLD: int = 5
DEFAULT_STRIKE_WINDOW_SECONDS: float = 60.0
DEFAULT_BAN_DURATION_SECONDS: int = 3600

DB_PATH = Path("data/waf.db")


def _is_whitelisted(ip: str) -> bool:
    """Check if the IP is explicitly whitelisted in configuration.

    Args:
        ip: The client IP address to check.

    Returns:
        True if the IP is whitelisted and immune to blacklisting, False otherwise.
    """
    if not ip:
        return False
    try:
        from waf.config_manager import get_config

        cfg = get_config()
        if cfg and hasattr(cfg, "whitelist_ips") and cfg.whitelist_ips:
            if ip in cfg.whitelist_ips:
                return True
    except Exception:
        pass
    return False


def _get_db_connection() -> Optional[sqlite3.Connection]:
    """Internal helper to obtain a database connection with blacklist table ensured."""
    try:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(DB_PATH), timeout=5.0)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS blacklist (
                ip TEXT PRIMARY KEY,
                reason TEXT NOT NULL,
                banned_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                strike_count INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        return conn
    except Exception as exc:
        logger.debug("Database connection unavailable for blacklist: %s", exc)
        return None


def load_from_db() -> None:
    """Load active, non-expired blacklist entries from SQLite into the in-memory set.

    Clears or synchronizes the internal `_blacklist` set with current active
    entries retrieved from the database blacklist table.
    """
    now = time.time()
    conn = _get_db_connection()
    if not conn:
        return

    try:
        with conn:
            cursor = conn.execute(
                "SELECT ip, expires_at FROM blacklist WHERE expires_at > ?",
                (now,),
            )
            rows = cursor.fetchall()
            _blacklist.clear()
            _expiry.clear()
            for ip_val, exp in rows:
                _blacklist.add(ip_val)
                _expiry[ip_val] = float(exp)

            # تنظيف السجلات منتهية الصلاحية من قاعدة البيانات
            conn.execute("DELETE FROM blacklist WHERE expires_at <= ?", (now,))
            logger.info("Loaded %d active blacklist entries from database", len(_blacklist))
    except Exception as exc:
        logger.warning("Failed to load blacklist from database: %s", exc)
    finally:
        conn.close()


def is_blacklisted(ip: str) -> bool:
    """Check whether an IP address is currently blacklisted.

    Validates presence against the fast in-memory set and verifies expiration.
    Auto-removes expired entries from memory and database storage when detected.

    Args:
        ip: The client IP address to test.

    Returns:
        True if the IP is currently banned, False otherwise.
    """
    if not ip or _is_whitelisted(ip):
        return False

    if ip not in _blacklist:
        return False

    now = time.time()
    expires_at = _expiry.get(ip)
    if expires_at is not None and now >= expires_at:
        # انتهت مدة الحظر: إزالة تلقائية
        remove(ip)
        return False

    return True


def add(
    ip: str,
    reason: str = "Automated strike threshold exceeded",
    duration_seconds: int = DEFAULT_BAN_DURATION_SECONDS,
) -> None:
    """Add an IP address to both the in-memory blacklist and persistent SQLite storage.

    Args:
        ip: The IP address to ban.
        reason: Justification or attack trigger description for the ban.
        duration_seconds: Duration of the ban in seconds before expiration.
    """
    if not ip or _is_whitelisted(ip):
        logger.info("Skipping blacklist addition for whitelisted IP: %s", ip)
        return

    now = time.time()
    expires_at = now + duration_seconds
    _blacklist.add(ip)
    _expiry[ip] = expires_at

    conn = _get_db_connection()
    if conn:
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO blacklist (ip, reason, banned_at, expires_at, strike_count)
                    VALUES (?, ?, ?, ?, 1)
                    ON CONFLICT(ip) DO UPDATE SET
                        reason = excluded.reason,
                        expires_at = excluded.expires_at,
                        strike_count = blacklist.strike_count + 1
                    """,
                    (ip, reason, now, expires_at),
                )
        except Exception as exc:
            logger.warning("Failed to persist blacklist entry for %s: %s", ip, exc)
        finally:
            conn.close()

    logger.warning("Blacklisted IP: %s for %ds (reason: %s)", ip, duration_seconds, reason)


def remove(ip: str) -> None:
    """Remove an IP address from both the in-memory blacklist and SQLite database.

    Args:
        ip: The IP address to unban.
    """
    if not ip:
        return

    _blacklist.discard(ip)
    _expiry.pop(ip, None)
    _strikes.pop(ip, None)

    conn = _get_db_connection()
    if conn:
        try:
            with conn:
                conn.execute("DELETE FROM blacklist WHERE ip = ?", (ip,))
        except Exception as exc:
            logger.warning("Failed to delete blacklist entry from DB for %s: %s", ip, exc)
        finally:
            conn.close()

    logger.info("Unbanned IP: %s", ip)


def record_strike(ip: str) -> None:
    """Record a block event strike against an IP and evaluate escalation rules.

    Appends the current timestamp to the strike list for the IP, purges strikes
    outside the sliding time window, and escalates to a blacklist ban if the strike
    count meets or exceeds the configured threshold.

    Args:
        ip: The client IP address that triggered a security block.
    """
    if not ip or _is_whitelisted(ip):
        return

    now = time.time()
    recent = [t for t in _strikes.get(ip, []) if (now - t) <= DEFAULT_STRIKE_WINDOW_SECONDS]
    recent.append(now)
    _strikes[ip] = recent

    if len(recent) >= DEFAULT_STRIKE_THRESHOLD:
        add(ip, reason="Automated strike threshold exceeded", duration_seconds=DEFAULT_BAN_DURATION_SECONDS)
        _strikes.pop(ip, None)