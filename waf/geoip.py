"""GeoIP enrichment module for AI-WAF.

Enriches incoming security events with geographical location data (country,
latitude, and longitude) using the MaxMind GeoLite2 City database.
"""

from __future__ import annotations

import logging
from typing import Optional

try:
    import geoip2.database
except ImportError:
    geoip2 = None  # type: ignore

from waf.models import WAFEvent

logger = logging.getLogger(__name__)

# Global MaxMind database reader instance
_reader: Optional[geoip2.database.Reader] = None


def init(db_path: str = "data/GeoLite2-City.mmdb") -> None:
    """Initialize the global GeoIP reader instance with the MMDB file.

    Args:
        db_path: File system path to the GeoLite2-City database file.
    """
    from pathlib import Path
    import importlib
    if geoip2 is None:raise RuntimeError('geoip2 is not installed')
    p=Path(db_path)
    if not p.is_file():raise FileNotFoundError(p)
    new_reader=geoip2.database.Reader(str(p))
    global _reader
    old_reader=_reader
    _reader=new_reader
    if old_reader is not None:old_reader.close()
    return None


def close() -> None:
    """Safely close and release resources held by the global GeoIP reader instance."""
    global _reader
    existing=_reader
    _reader=None
    if existing is not None:existing.close()
    return None


def enrich(event: WAFEvent) -> WAFEvent:
    """Enrich a WAFEvent with geographic metadata based on client IP.

    Looks up the client IP address in the GeoIP database to resolve country
    code/name, latitude, and longitude. Updates the relevant fields on the event
    object. If lookup fails or the reader is uninitialized, returns the event unchanged.

    Args:
        event: The incoming WAFEvent to enrich.

    Returns:
        The WAFEvent instance with geographical fields populated if resolution succeeded.
    """
    import ipaddress
    if not isinstance(event,WAFEvent):raise TypeError('Expected WAFEvent')
    if _reader is None:return event
    try:
        address=ipaddress.ip_address(event.client_ip)
    except ValueError:return event
    if not address.is_global:return event
    try:
        record=_reader.city(str(address))
        country=record.country.iso_code or record.country.name
        lat=record.location.latitude
        lon=record.location.longitude
        if country:event.country=str(country)
        if lat is not None and lon is not None:
            event.latitude=float(lat)
            event.longitude=float(lon)
    except Exception as exc:
        logger.warning('GeoIP lookup unavailable: %s',type(exc).__name__)
    return event
