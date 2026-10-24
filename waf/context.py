"""Request Context Builder."""

from __future__ import annotations

import dataclasses
import json
import logging
import time
import urllib.parse
import uuid
from typing import Any, Dict

from fastapi import HTTPException, Request

from waf.models import RequestContext

logger = logging.getLogger("ai_waf.context")

MAX_BODY_SIZE: int = 1_048_576  # 1 MB maximum payload limit

_CTX_FIELDS = {f.name for f in dataclasses.fields(RequestContext)}


def _flatten(value: Any, prefix: str = "") -> Dict[str, Any]:
    """Flatten nested JSON so every leaf value gets normalized and inspected."""
    out: Dict[str, Any] = {}
    if isinstance(value, dict):
        for k, v in value.items():
            out.update(_flatten(v, f"{prefix}.{k}" if prefix else str(k)))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            out.update(_flatten(v, f"{prefix}[{i}]"))
    else:
        out[prefix or "_root"] = value
    return out


async def build_context(request: Request) -> RequestContext:
    """Build a RequestContext from an incoming FastAPI HTTP request."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    headers = dict(request.headers)  # Starlette lowercases header names
    content_type = headers.get("content-type", "").lower()

    # Reject early based on the declared size, before reading anything into memory.
    declared = headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > MAX_BODY_SIZE:
                raise HTTPException(status_code=413, detail="Payload Too Large")
        except ValueError:
            pass

    raw_body = await request.body()
    if len(raw_body) > MAX_BODY_SIZE:
        raise HTTPException(status_code=413, detail="Payload Too Large")

    body_fields: Dict[str, Any] = {}
    if raw_body:
        try:
            text = raw_body.decode("utf-8", errors="replace")
            if "application/json" in content_type:
                body_fields = _flatten(json.loads(text))
            elif "application/x-www-form-urlencoded" in content_type:
                for k, v in urllib.parse.parse_qsl(text, keep_blank_values=True):
                    # keep duplicate keys (HTTP parameter pollution) instead of dropping them
                    body_fields[k] = f"{body_fields[k]},{v}" if k in body_fields else v
        except Exception:
            logger.debug("Body could not be parsed (content-type=%s)", content_type)

    kwargs: Dict[str, Any] = dict(
        client_ip=client_ip,
        method=request.method,
        path=request.url.path,
        query_string=request.url.query,
        headers=headers,
        body_raw=raw_body,
        body_fields=body_fields,
    )
    # Only pass the extra fields if waf/models.py defines them (spec section 6.1).
    extras = {"request_id": str(uuid.uuid4()), "timestamp": time.time(), "content_type": content_type}
    kwargs.update({k: v for k, v in extras.items() if k in _CTX_FIELDS})

    return RequestContext(**kwargs)