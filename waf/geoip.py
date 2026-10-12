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
    pass


def close() -> None:
    """Safely close and release resources held by the global GeoIP reader instance."""
    pass


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
    pass
