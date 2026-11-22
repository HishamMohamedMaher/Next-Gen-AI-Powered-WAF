"""Threat intelligence integration module for AI-WAF.

Provides automated IP reputation lookups via the AbuseIPDB API,
caching responses locally to avoid unnecessary API consumption and
filtering private network addresses.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import sqlite3
from typing import Any, Dict, Optional

import httpx

from waf import db

logger = logging.getLogger(__name__)

ABUSEIPDB_URL: str = "https://api.abuseipdb.com/api/v2/check"

def _is_private(ip: str) -> bool:
    """Return whether the address is unsuitable for public reputation lookups."""
    address = ipaddress.ip_address(ip)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return (
        not address.is_global or address.is_multicast or address.is_reserved
        or (isinstance(address, ipaddress.IPv6Address) and address.is_site_local)
    )


def _validate_result(ip: str, result: Any) -> bool:
    if not isinstance(result, dict):
        return False
    address = result.get('ipAddress')
    if not isinstance(address, str):
        return False
    try:
        if ipaddress.ip_address(address) != ipaddress.ip_address(ip):
            return False
    except ValueError:
        return False
    score = result.get('abuseConfidenceScore')
    if type(score) is not int or not 0 <= score <= 100:
        return False
    if result.get('isPublic', True) is not True:
        return False
    total = result.get('totalReports', 0)
    return type(total) is int and total >= 0


def _cache_get(ip: str) -> Optional[Dict[str, Any]]:
    """Retrieve cached threat intelligence result for an IP address.

    Args:
        ip: The target IP address.

    Returns:
        A dictionary containing cached reputation data if available and fresh,
        or None if missing or expired.
    """
    record = db.get_abuseipdb_cache(ip, max_age_hours=24)
    if record is None:
        return None
    try:
        result = json.loads(record['raw_response'])
    except (ValueError, TypeError, KeyError):
        return None
    return result if _validate_result(ip, result) else None


def _cache_set(ip: str, result: Dict[str, Any]) -> None:
    """Store or update threat intelligence lookup result in local database cache.

    Args:
        ip: The target IP address.
        result: The lookup payload containing abuse score and metadata.
    """
    if not isinstance(result, dict):
        raise TypeError('Expected dictionary')
    if not _validate_result(ip, result):
        raise ValueError('Invalid reputation response')
    db.cache_abuseipdb(ip, result['abuseConfidenceScore'], json.dumps(result, ensure_ascii=False))


def lookup(ip: str) -> Optional[Dict[str, Any]]:
    """Query AbuseIPDB API for threat reputation details on the specified IP.

    Checks private IP ranges first to avoid external calls. Checks local cache
    before dispatching an HTTP request with the API key loaded from environment
    variables (`ABUSEIPDB_API_KEY`). Stores successful queries to the database cache.

    Args:
        ip: The IPv4 or IPv6 string to evaluate.

    Returns:
        A dictionary containing threat details (e.g., abuseConfidenceScore,
        countryCode, usageType, totalReports), or None for private IPs or failed queries.
    """
    if not isinstance(ip, str) or '%' in ip:
        return None
    try:
        if _is_private(ip):
            return None
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    ip = str(address)

    try:
        result = _cache_get(ip)
        if result is not None:
            return result
    except (OSError, ValueError, sqlite3.Error) as exc:
        logger.warning('Threat cache read failed: %s', type(exc).__name__)

    api_key = os.environ.get('ABUSEIPDB_API_KEY', '').strip()
    if not api_key:
        return None
    try:
        response = httpx.get(
            ABUSEIPDB_URL,
            params={'ipAddress': ip, 'maxAgeInDays': 90},
            headers={'Key': api_key, 'Accept': 'application/json'},
            timeout=2.0,
            follow_redirects=False,
        )
        response.raise_for_status()
        envelope = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning('AbuseIPDB lookup failed: %s', type(exc).__name__)
        return None
    result = envelope.get('data') if isinstance(envelope, dict) else None
    if not _validate_result(ip, result):
        return None
    try:
        _cache_set(ip, result)
    except (OSError, ValueError, sqlite3.Error) as exc:
        logger.warning('Threat cache write failed: %s', type(exc).__name__)
    return result
