"""AI-WAF Core FastAPI Application and Gateway Entrypoint.

This module provides the primary reverse-proxy HTTP interface, managing the
full request evaluation pipeline: context building, normalization, multi-layer
threat detection, upstream proxy forwarding, and event logging.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
import logging
from typing import AsyncGenerator

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from waf.context import build_context
from waf.models import Action, DetectionResult, RequestContext, WAFEvent
from waf.normalizer import normalize_context
from waf.proxy import close_client, forward, init_client

# Setup structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("ai_waf")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application startup and shutdown lifecycle tasks.

    Startup:
    - Loads WAF configuration.
    - Initializes the HTTPX reverse-proxy client.
    - Loads signature detection rules into memory.
    - Loads and initializes AI threat detection models.
    - Performs model warmup inference.
    - Starts the background asynchronous event writer.

    Shutdown:
    - Closes HTTPX client connection pools.
    - Flushes remaining pending security events in the queue.
    """
    # Startup sequence
    logger.info("Initializing HTTPX Client...")
    await init_client()
    try:
        yield
    finally:
        # Shutdown sequence
        logger.info("Closing HTTPX Client...")
        await close_client()


app = FastAPI(
    title="AI-WAF Security Gateway",
    description="Intelligent Web Application Firewall with Hybrid Rules and Machine Learning Detection",
    version="1.0.0",
    lifespan=lifespan,
)


@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def catch_all(request: Request, path: str) -> Response:
    """Catch-all HTTP handler routing requests through WAF inspection.

    Pipeline:
    1. Build raw RequestContext from HTTP request.
    2. Normalize context payload fields (URL decode, HTML entities, SQL comments, etc.).
    3. Run detection pipeline across layers (whitelist, blacklist, rate limit, signatures, AI).
    4. Enforce security decision (block with 403 or forward to backend service).
    5. Asynchronously queue WAFEvent for storage and analytics.

    Args:
        request: Incoming HTTP request.
        path: Path captured from the request URL.

    Returns:
        Upstream Response if allowed, or JSONResponse (403 Forbidden) if blocked.
    """
    # Temporary Day 1 implementation to verify the gateway is receiving traffic
    ctx = RequestContext(
        method=request.method,
        path=request.url.path,
        client_ip=request.client.host if request.client else "127.0.0.1",
        request_id="test-id-123"
    )
    
    return JSONResponse(content={
        "status": "success",
        "message": "AI-WAF Core Gateway is actively listening on port 8080!",
        "intercepted_path": ctx.path,
        "method": ctx.method
    })