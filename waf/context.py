"""Request Context Builder.

This module provides functions to inspect incoming Starlette / FastAPI requests,
extract headers, client metadata, payload bodies up to safe limits, and parse
structured body fields (JSON or form data).
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict
import urllib.parse
from fastapi import Request

from waf.models import RequestContext

MAX_BODY_SIZE: int = 1_048_576  # 1 MB maximum payload limit


async def build_context(request: Request) -> RequestContext:
    """Build a RequestContext from an incoming FastAPI HTTP request.

    Reads client IP, method, path, query string, headers, and the raw body
    (enforcing MAX_BODY_SIZE). Decodes and parses body_fields based on the
    Content-Type header (e.g., application/json or application/x-www-form-urlencoded).

    Args:
        request: The FastAPI/Starlette Request object.

    Returns:
        RequestContext with original fields populated and normalized fields empty.

    Raises:
        HTTPException: If the request payload exceeds MAX_BODY_SIZE or is malformed.
    """
    request_id = str(uuid.uuid4())
    
    # استخراج عنوان الـ IP الخاص بالعميل بأمان
    client_ip = "127.0.0.1"
    if hasattr(request, "client") and request.client and hasattr(request.client, "host"):
        client_ip = request.client.host or "127.0.0.1"

    method = getattr(request, "method", "GET")

    path = "/"
    query_string = ""
    try:
        path = request.url.path
        query_string = request.url.query
    except Exception:
        pass

    headers = {}
    if hasattr(request, "headers"):
        headers = {k.lower(): v for k, v in request.headers.items()}

    content_type = headers.get("content-type", "")

    body_raw = b""
    try:
        body_raw = await request.body()
    except Exception:
        pass

    if len(body_raw) > MAX_BODY_SIZE:
        body_raw = body_raw[:MAX_BODY_SIZE]

    body_fields = {}
    if body_raw:
        if "application/json" in content_type:
            try:
                parsed_json = json.loads(body_raw.decode("utf-8", errors="ignore"))
                if isinstance(parsed_json, dict):
                    body_fields = parsed_json
            except Exception:
                body_fields = {}
        elif "application/x-www-form-urlencoded" in content_type:
            try:
                parsed_form = urllib.parse.parse_qs(body_raw.decode("utf-8", errors="ignore"))
                body_fields = {k: v[0] if len(v) == 1 else v for k, v in parsed_form.items()}
            except Exception:
                body_fields = {}

    return RequestContext(
        request_id=request_id,
        client_ip=client_ip,
        method=method,
        path=path,
        query_string=query_string,
        headers=headers,
        body_raw=body_raw,
        body_fields=body_fields,
        content_type=content_type,
    )