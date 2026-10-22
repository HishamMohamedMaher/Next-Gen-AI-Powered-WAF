"""Reverse Proxy Module.

Handles forwarding validated HTTP requests to the upstream backend service,
stripping hop-by-hop headers, managing connection pools, and handling backend timeouts/errors.
"""

from __future__ import annotations

import os
from typing import Optional
from fastapi import Request, Response
import httpx

from waf.models import RequestContext

BACKEND_URL: str = os.getenv("BACKEND_URL", "http://localhost:3000")

HOP_BY_HOP: frozenset[str] = frozenset({
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
})

_client: Optional[httpx.AsyncClient] = None


async def init_client() -> None:
    """Initialize the global httpx.AsyncClient instance with connection pooling."""
    global _client
    _client = httpx.AsyncClient(
        limits=httpx.Limits(max_keepalive_connections=50, max_connections=200)
    )


async def close_client() -> None:
    """Close the global httpx.AsyncClient instance cleanly."""
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


async def forward(request: Request, ctx: RequestContext) -> Response:
    """Forward an incoming request to the upstream backend service.

    Removes hop-by-hop headers, appends/updates X-Forwarded-For, preserves
    request body and query parameters, and handles upstream errors (returning 502 Bad Gateway).

    Args:
        request: The original FastAPI/Starlette Request.
        ctx: Evaluated RequestContext containing request metadata.

    Returns:
        FastAPI Response containing backend status code, headers, and body content.
    """
    pass