"""Text and Request Normalization Engine.

================================================================================
CRITICAL WARNING: SHARED MODULE
This file is strictly shared between the real-time WAF inference engine and the
offline model training pipeline. Any modification to text transformations or
normalization order here MUST be synchronized with the training dataset preparation,
or severe feature mismatch and detection degradation will occur.
================================================================================
"""

from __future__ import annotations

from dataclasses import dataclass
import html
import re
import unicodedata
from typing import  Dict

from waf.models import RequestContext

MAX_DECODE_ITERATIONS: int = 5


@dataclass
class NormalizedResult:
    """Represents the output of text normalization."""

    original: str
    normalized: str
    decode_iterations: int



from urllib.parse import unquote

def _iterative_url_decode(text: str, max_iterations: int = 5) -> tuple[str, int]:
    """Iteratively URL-decode text until it stabilizes or hits the iteration limit."""
    current = text
    iterations = 0

    while iterations < max_iterations:
        decoded = unquote(current)
        if decoded == current:
            break
        current = decoded
        iterations += 1

    return current, iterations


import html

def _decode_html_entities(text: str) -> str:
    """Decode HTML entities (named, decimal, hex) to plain text."""
    if not text:
        return ""
    return html.unescape(text)



import unicodedata

def _normalize_unicode(text: str) -> str:
    """Normalize Unicode characters using NFKC decomposition."""
    if not text:
        return ""
    return unicodedata.normalize("NFKC", text)


def _strip_null_bytes(text: str) -> str:
    """Remove null bytes and null-byte representations from text."""
    if not text:
        return ""
    text = text.replace("\x00", "").replace("%00", "").replace("\\0", "") 
   
    return text

import re

def _strip_comments(text: str) -> str:
    """Replace SQL inline comments (/* ... */) with a single space."""
    if not text:
        return ""
    cleaned = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"\s+", " ", cleaned).strip()



def _extract_mysql_conditional_comments(text: str) -> str:

    if not text:
        return ""
    return re.sub(r"/\*!(?:\d{5})?\s*(.*?)\s*\*/", r" \1 ", text, flags=re.DOTALL).strip()


def _to_lowercase(text: str) -> str:
   
    if not text:
        return ""
    return text.lower()


def normalize_text(text: str) -> NormalizedResult:
    
    if not text:
        return NormalizedResult(original="", normalized="", decode_iterations=0)

    current, iterations = _iterative_url_decode(text, MAX_DECODE_ITERATIONS)

    current = _decode_html_entities(current)

    current = _normalize_unicode(current)

    current = _strip_null_bytes(current)

    current = _strip_comments(current)

    current = _extract_mysql_conditional_comments(current)

    current = _to_lowercase(current)
    current = re.sub(r"\s+", " ", current).strip()

    return NormalizedResult(
        original=text,
        normalized=current,
        decode_iterations=iterations,
    )


def normalize_context(ctx: RequestContext) -> RequestContext:
    """
    Normalize all extractable payload fields in a RequestContext.
    Normalizes path, query string, and each string value inside body_fields,
    recording the maximum decode iterations encountered.
    """
    max_iterations = 0

    if ctx.path:
        res = normalize_text(ctx.path)
        ctx.path_normalized = res.normalized
        max_iterations = max(max_iterations, res.decode_iterations)
    else:
        ctx.path_normalized = ""

    if ctx.query_string:
        res = normalize_text(ctx.query_string)
        ctx.query_normalized = res.normalized
        max_iterations = max(max_iterations, res.decode_iterations)
    else:
        ctx.query_normalized = ""

    normalized_body: Dict[str, str] = {}
    if ctx.body_fields:
        for key, value in ctx.body_fields.items():
            if isinstance(value, str):
                res = normalize_text(value)
                normalized_body[key] = res.normalized
                max_iterations = max(max_iterations, res.decode_iterations)
            else:
                normalized_body[key] = str(value)

    ctx.body_fields_normalized = normalized_body
    ctx.decode_iterations = max_iterations

    return ctx