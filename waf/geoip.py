"""Enrich WAF events with data from a local City database in MMDB format."""

from __future__ import annotations

import ipaddress
import logging
from pathlib import Path
from threading import Lock
from typing import Optional

try:
    import geoip2.database
    import geoip2.errors
    from maxminddb.errors import InvalidDatabaseError
except ImportError:
    geoip2 = None  # type: ignore

from waf.models import WAFEvent
from waf.threat_intel import _is_private

logger = logging.getLogger(__name__)
_reader: Optional[geoip2.database.Reader] = None
_reader_lock = Lock()


def init(db_path: str = "data/GeoLite2-City.mmdb") -> None:
    """Open a City database, preserving any reader already working if open fails."""
    if geoip2 is None:
        logger.warning('GeoIP enrichment unavailable: geoip2 is not installed')
        return
    path = Path(db_path)
    if not path.is_file():
        logger.info('GeoIP enrichment database unavailable at %s', path)
        return
    reader = None
    try:
        reader = geoip2.database.Reader(str(path))
        # Match Reader.city() compatibility, including DB-IP City databases.
        if 'City' not in reader.metadata().database_type:
            raise ValueError('Expected a City database in MMDB format')
    except (OSError, ValueError, InvalidDatabaseError) as exc:
        if reader is not None:
            reader.close()
        logger.warning('GeoIP reader unavailable: %s', type(exc).__name__)
        return

    global _reader
    with _reader_lock:
        previous = _reader
        _reader = reader
        if previous is not None:
            previous.close()


def close() -> None:
    """Release the active GeoIP reader."""
    global _reader
    with _reader_lock:
        if _reader is not None:
            reader, _reader = _reader, None
            reader.close()


def enrich(event: WAFEvent) -> WAFEvent:
    """Populate geographic fields on the supplied WAF event when available."""
    if not isinstance(event, WAFEvent):
        raise TypeError('Expected WAFEvent')
    try:
        if _is_private(event.client_ip):
            return event
        address = ipaddress.ip_address(event.client_ip)
    except ValueError:
        return event
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    with _reader_lock:
        if _reader is None:
            return event
        try:
            record = _reader.city(str(address))
        except geoip2.errors.AddressNotFoundError:
            return event
        except (OSError, ValueError, InvalidDatabaseError, geoip2.errors.GeoIP2Error) as exc:
            logger.warning('GeoIP lookup unavailable: %s', type(exc).__name__)
            return event
    country = record.country.iso_code or record.country.name
    if country:
        event.country = country
    latitude, longitude = record.location.latitude, record.location.longitude
    if latitude is not None and longitude is not None:
        event.latitude = float(latitude)
        event.longitude = float(longitude)
    return event
