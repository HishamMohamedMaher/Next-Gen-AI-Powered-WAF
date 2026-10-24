"""Reverse Proxy Module."""

from __future__ import annotations

import logging
import os
from typing import Optional

import httpx
from fastapi import Request, Response

try:  # python-dotenv is in requirements.txt, but don't crash if it's missing
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover
    pass

from waf.models import RequestContext

logger = logging.getLogger("ai_waf.proxy")

BACKEND_URL: str = os.getenv("BACKEND_URL", "http://127.0.0.1:3000").strip().rstrip("/")

if not BACKEND_URL.startswith(("http://", "https://")):
    # Catches the classic copy/paste bug: "[http://x](http://x)" or a missing scheme.
    logger.error("BACKEND_URL looks invalid: %r", BACKEND_URL)

HOP_BY_HOP: frozenset[str] = frozenset({
    "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers",
    "transfer-encoding", "upgrade",
})

# httpx already decodes gzip/br bodies, so these two no longer describe `.content`.
_STRIP_FROM_RESPONSE: frozenset[str] = HOP_BY_HOP | {"content-encoding", "content-length"}
_STRIP_FROM_REQUEST: frozenset[str] = HOP_BY_HOP | {"host", "content-length"}

_client: Optional[httpx.AsyncClient] = None


async def init_client() -> None:
    """Initialize the global httpx.AsyncClient (with connection pooling)."""
    global _client
    _client = httpx.AsyncClient(
        timeout=httpx.Timeout(10.0, connect=3.0),
        limits=httpx.Limits(max_keepalive_connections=50, max_connections=200),
        follow_redirects=False,
    )


async def close_client() -> None:
    """Close the global httpx.AsyncClient instance cleanly."""
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


async def forward(request: Request, ctx: RequestContext) -> Response:
    """Forward an incoming request to the upstream backend service."""
    if _client is None:
        return Response(content="500 Internal Server Error: Client not initialized", status_code=500)

    target_url = f"{BACKEND_URL}{ctx.path}"
    if ctx.query_string:
        target_url = f"{target_url}?{ctx.query_string}"

    clean_headers = {k: v for k, v in ctx.headers.items() if k.lower() not in _STRIP_FROM_REQUEST}

    prior = ctx.headers.get("x-forwarded-for")
    clean_headers["x-forwarded-for"] = f"{prior}, {ctx.client_ip}" if prior else ctx.client_ip

    body = await request.body()

    try:
        upstream_resp = await _client.request(
            method=ctx.method,
            url=target_url,
            headers=clean_headers,
            content=body,
        )
    except (httpx.RequestError, httpx.InvalidURL) as exc:
        # Log the REAL reason - "Backend is unreachable" alone hides the cause.
        logger.error("Upstream failed: %s: %s | url=%s", type(exc).__name__, exc, target_url)
        return Response(content="502 Bad Gateway: Backend is unreachable", status_code=502)

    resp_headers = {k: v for k, v in upstream_resp.headers.items() if k.lower() not in _STRIP_FROM_RESPONSE}
    return Response(content=upstream_resp.content, status_code=upstream_resp.status_code, headers=resp_headers)