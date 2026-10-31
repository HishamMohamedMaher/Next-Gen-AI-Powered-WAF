"""Structural and Lexical Feature Extraction Engine.

This module extracts numerical, statistical, and lexical features from HTTP
request payloads for feeding machine learning classifiers and anomaly detectors.
It also prepares concatenated textual inputs for TF-IDF vectorization.
"""

from __future__ import annotations

import math
from typing import List, Set
from collections import Counter
import numpy as np

from waf.models import RequestContext

# Canonical list of 12 numerical feature names extracted from request contexts
FEATURE_NAMES: List[str] = [
    "payload_length",
    "shannon_entropy",
    "special_char_ratio",
    "digit_ratio",
    "uppercase_ratio",
    "sql_keyword_count",
    "xss_char_count",
    "path_depth",
    "query_param_count",
    "max_param_length",
    "non_ascii_count",
    "decode_iterations",
]

# Set of standard SQL syntax keywords and functions targeted by SQLi attacks
SQL_KEYWORDS: frozenset[str] = frozenset({
    "select",
    "insert",
    "update",
    "delete",
    "drop",
    "union",
    "order by",
    "group by",
    "where",
    "from",
    "having",
    "exec",
    "declare",
    "cast",
    "convert",
    "table",
    "schema",
    "information_schema",
    "xp_cmdshell",
    "benchmark",
    "sleep",
    "waitfor",
    "or",
    "and",
    "xor",
    "not",
    "null",
    "like",
})

# String of special characters indicative of injection, escaping, or script injection
SPECIAL_CHARS: str = r"""'"<>;:()[]{}=+\-/*%&|^~`$@#!?"""


def _shannon_entropy(text: str) -> float:
    """Calculate the Shannon entropy of a given text string.

    Computes information entropy based on character frequency distribution,
    providing a metric for obfuscation, high randomness, or encoding artifacts.

    Args:
        text: Input string to evaluate.

    Returns:
        Shannon entropy value in bits (0.0 for empty strings).
    """
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    counts = Counter(text)
    for count in counts.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return entropy


def extract_text_for_tfidf(ctx: RequestContext) -> str:
    """Combine normalized path, query parameters, and body values into a unified text.

    Flattens hierarchical request fields into a single representative string
    suitable for n-gram feature extraction and TF-IDF vectorization.

    Args:
        ctx: Evaluated RequestContext containing normalized fields.

    Returns:
        Concatenated text representation of the request.
    """
    parts = []
    if hasattr(ctx, "path") and ctx.path:
        parts.append(str(ctx.path))

    q_params = getattr(ctx, "normalized_query", None)
    if q_params is None:
        q_params = getattr(ctx, "query_params", {})

    if isinstance(q_params, dict):
        for k, v in q_params.items():
            parts.append(f"{k}={v}")
    elif isinstance(q_params, str):
        parts.append(q_params)

    body = getattr(ctx, "normalized_body", None)
    if body is None:
        body = getattr(ctx, "body", "")
    if isinstance(body, bytes):
        try:
            body = body.decode("utf-8", errors="ignore")
        except Exception:
            body = ""
    if body:
        parts.append(str(body))

    return " ".join(parts)


def extract(ctx: RequestContext) -> np.ndarray:
    """Extract 12 structural and statistical features from the request context.

    Features extracted correspond to FEATURE_NAMES:
    1. payload_length: Total character length of combined text.
    2. shannon_entropy: Entropy of combined text.
    3. special_char_ratio: Ratio of characters in SPECIAL_CHARS.
    4. digit_ratio: Ratio of numeric digits.
    5. uppercase_ratio: Ratio of uppercase ASCII letters.
    6. sql_keyword_count: Frequency of matched SQL keywords.
    7. xss_char_count: Count of script tags or typical XSS symbols (<, >, quotes).
    8. path_depth: Directory depth inferred from slashes in path.
    9. query_param_count: Total count of query parameters.
    10. max_param_length: Maximum length among parameter keys and values.
    11. non_ascii_count: Count of non-ASCII or high-byte characters.
    12. decode_iterations: Decode rounds performed during normalization.

    Args:
        ctx: Populated RequestContext.

    Returns:
        1D numpy float array of shape (12,) containing feature values.
    """
    text = extract_text_for_tfidf(ctx)
    length = len(text)

    payload_length = float(length)
    shannon_entropy = _shannon_entropy(text)

    if length > 0:
        special_count = sum(1 for c in text if c in SPECIAL_CHARS)
        special_char_ratio = special_count / length
        digit_count = sum(1 for c in text if c.isdigit())
        digit_ratio = digit_count / length
        upper_count = sum(1 for c in text if c.isupper())
        uppercase_ratio = upper_count / length
    else:
        special_char_ratio = 0.0
        digit_ratio = 0.0
        uppercase_ratio = 0.0

    text_lower = text.lower()
    sql_keyword_count = float(sum(1 for kw in SQL_KEYWORDS if kw in text_lower))

    xss_chars = {"<", ">", '"', "'"}
    xss_char_count = float(sum(1 for c in text if c in xss_chars))

    path = getattr(ctx, "path", "") or ""
    path_depth = float(path.strip("/").count("/")) + (1.0 if path and path != "/" else 0.0) if path else 0.0

    q_params = getattr(ctx, "normalized_query", None)
    if q_params is None:
        q_params = getattr(ctx, "query_params", {})
    query_param_count = float(len(q_params)) if isinstance(q_params, (dict, list, set)) else 0.0

    max_param_length = 0.0
    if isinstance(q_params, dict):
        for k, v in q_params.items():
            max_param_length = max(max_param_length, float(len(str(k)) + len(str(v))))
    elif isinstance(q_params, str):
        max_param_length = float(len(q_params))

    non_ascii_count = float(sum(1 for c in text if ord(c) > 127))
    decode_iterations = float(getattr(ctx, "decode_iterations", 1.0))

    features = [
        payload_length,
        shannon_entropy,
        special_char_ratio,
        digit_ratio,
        uppercase_ratio,
        sql_keyword_count,
        xss_char_count,
        path_depth,
        query_param_count,
        max_param_length,
        non_ascii_count,
        decode_iterations,
    ]

    return np.array(features, dtype=float)