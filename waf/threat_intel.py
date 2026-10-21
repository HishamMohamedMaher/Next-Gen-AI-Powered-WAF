"""Threat intelligence integration module for AI-WAF.

Provides automated IP reputation lookups via the AbuseIPDB API,
caching responses locally to avoid unnecessary API consumption and
filtering private network addresses.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

ABUSEIPDB_URL: str = "https://api.abuseipdb.com/api/v2/check"

PRIVATE_RANGES: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_private(ip: str) -> bool:
    """Check if the given IP address falls within private or loopback ranges.

    Args:
        ip: The IPv4 or IPv6 string to validate.

    Returns:
        True if the IP is within a private/reserved subnet, False otherwise.
    """
    address=ipaddress.ip_address(ip)
    return not address.is_global


def _cache_get(ip: str) -> Optional[Dict[str, Any]]:
    """Retrieve cached threat intelligence result for an IP address.

    Args:
        ip: The target IP address.

    Returns:
        A dictionary containing cached reputation data if available and fresh,
        or None if missing or expired.
    """
    import json
    from waf import db
    record=db.get_abuseipdb_cache(ip,max_age_hours=24)
    if not record:return None
    try:
        result=json.loads(record['raw_response'])
    except (ValueError,TypeError,KeyError):return None
    return result if isinstance(result,dict) else None


def _cache_set(ip: str, result: Dict[str, Any]) -> None:
    """Store or update threat intelligence lookup result in local database cache.

    Args:
        ip: The target IP address.
        result: The lookup payload containing abuse score and metadata.
    """
    import json
    from waf import db
    if not isinstance(result,dict):raise TypeError('Expected dictionary')
    score=result.get('abuseConfidenceScore',0)
    if isinstance(score,bool) or not isinstance(score,(int,float)) or not 0<=score<=100:
        raise ValueError('Invalid abuse confidence score')
    db.cache_abuseipdb(ip,int(score),json.dumps(result,ensure_ascii=False))
    return None


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
    import json, urllib.request, urllib.parse
    try:
        if _is_private(ip):return None
    except ValueError:return None
    try:
        result=_cache_get(ip)
        if result is not None:return result
    except Exception as exc:
        logger.warning('Threat cache read failed: %s',type(exc).__name__)
    api_key=os.environ.get('ABUSEIPDB_API_KEY','').strip()
    if not api_key:return None
    url=ABUSEIPDB_URL+'?'+urllib.parse.urlencode({'ipAddress':ip,'maxAgeInDays':90})
    request=urllib.request.Request(url,headers={'Key':api_key,'Accept':'application/json'})
    try:
        with urllib.request.urlopen(request,timeout=2.0) as response:
            raw=response.read(1024*1024)
        envelope=json.loads(raw)
        result=envelope.get('data') if isinstance(envelope,dict) else None
        if not isinstance(result,dict):return None
        if result.get('ipAddress')!=ip:return None
        try:_cache_set(ip,result)
        except Exception as exc:logger.warning('Threat cache write failed: %s',type(exc).__name__)
        return result
    except Exception as exc:
        logger.warning('AbuseIPDB lookup failed: %s',type(exc).__name__)
        return None
