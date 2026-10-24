"""AI-WAF Core FastAPI Application and Gateway Entrypoint."""

from __future__ import annotations
from contextlib import asynccontextmanager
import logging
from typing import AsyncGenerator

from fastapi import FastAPI, Request, Response
from waf.context import build_context
from waf.normalizer import normalize_context
from waf.proxy import close_client, forward, init_client

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("ai_waf")

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info("Initializing HTTPX Client...")
    await init_client()
    try:
        yield
    finally:
        logger.info("Closing HTTPX Client...")
        await close_client()

app = FastAPI(title="AI-WAF Security Gateway", version="1.0.0", lifespan=lifespan)

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def catch_all(request: Request, path: str) -> Response:
      ctx = await build_context(request)
      ctx = normalize_context(ctx) 
      return await forward(request, ctx)