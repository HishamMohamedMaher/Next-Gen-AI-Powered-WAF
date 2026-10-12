"""Request Context Builder.

This module provides functions to inspect incoming Starlette / FastAPI requests,
extract headers, client metadata, payload bodies up to safe limits, and parse
structured body fields (JSON or form data).
"""

from __future__ import annotations

import json
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
    pass
