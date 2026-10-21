"""Structural and Lexical Feature Extraction Engine.

This module extracts numerical, statistical, and lexical features from HTTP
request payloads for feeding machine learning classifiers and anomaly detectors.
It also prepares concatenated textual inputs for TF-IDF vectorization.
"""

from __future__ import annotations

import math
from typing import List, Set
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
SPECIAL_CHARS: str = "\"'<>;:()[]{}=+\\-/*%&|^~`$@#!?"


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

    length = len(text)
    frequencies = {}

    for char in text:
        frequencies[char] = frequencies.get(char, 0) + 1

    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in frequencies.values()
    )

    return float(entropy)


def extract_text_for_tfidf(ctx: RequestContext) -> str:
    """Combine normalized path, query parameters, and body values into a unified text.

    Flattens hierarchical request fields into a single representative string
    suitable for n-gram feature extraction and TF-IDF vectorization.

    Args:
        ctx: Evaluated RequestContext containing normalized fields.

    Returns:
        Concatenated text representation of the request.
    """
    import json

    if not isinstance(ctx, RequestContext):
        raise TypeError("Expected RequestContext")

    # Require the shared normalization stage first.
    if ctx.path and not ctx.path_normalized:
        raise ValueError("Path normalization is required")

    if ctx.query_string and not ctx.query_normalized:
        raise ValueError("Query normalization is required")

    normalized_body = ctx.body_fields_normalized

    if not isinstance(normalized_body, dict):
        raise ValueError("Normalized body must be a dictionary")

    # No raw body fields may silently bypass normalization.
    if ctx.body_fields:
        if set(ctx.body_fields) != set(normalized_body):
            raise ValueError("Body normalization is incomplete")

    # Do not silently ignore an unparsed HTTP body.
    if ctx.body_raw and not ctx.body_fields and not normalized_body:
        raise ValueError("Raw HTTP body requires parsing and normalization")

    if any(
        not isinstance(key, str)
        for key in normalized_body
    ):
        raise ValueError("Body field names must be strings")

    # Stable representation; no headers, cookies or client IP.
    canonical = {
        "path": ctx.path_normalized,
        "query": ctx.query_normalized,
        "body": {
            key: str(normalized_body[key])
            for key in sorted(normalized_body)
        },
    }

    # Deterministic text, independent of dictionary insertion order.
    return json.dumps(
        canonical,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":")
    )


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
    import re

    if not isinstance(ctx, RequestContext):
        raise TypeError("Expected RequestContext")

    # Reuse the existing text extractor as the normalization gate.
    # It rejects incomplete normalization and unparsed raw bodies.
    extract_text_for_tfidf(ctx)

    if (
        isinstance(ctx.decode_iterations, bool)
        or not isinstance(ctx.decode_iterations, int)
        or ctx.decode_iterations < 0
    ):
        raise ValueError("Invalid decode_iterations")

    # Build a text representation without artificial JSON punctuation.
    parts = [
        ctx.path_normalized,
        ctx.query_normalized,
    ]

    for key in sorted(ctx.body_fields_normalized):
        value = ctx.body_fields_normalized[key]
        parts.append(f"{key}={value}")

    text = " ".join(
        part for part in parts if part
    )

    length = len(text)

    # 1. Payload length
    payload_length = length

    # 2. Shannon entropy
    entropy = _shannon_entropy(text)

    # 3. Special-character ratio
    special_char_ratio = (
        sum(ch in SPECIAL_CHARS for ch in text) / length
        if length else 0.0
    )

    # 4. Digit ratio
    digit_ratio = (
        sum(ch.isdigit() for ch in text) / length
        if length else 0.0
    )

    # 5. Uppercase ASCII ratio
    uppercase_ratio = (
        sum("A" <= ch <= "Z" for ch in text) / length
        if length else 0.0
    )

    # 6. SQL keyword count
    # Match complete tokens/phrases rather than substrings.
    lower_text = text.lower()

    sql_keyword_count = 0

    for keyword in SQL_KEYWORDS:

        escaped = re.escape(keyword).replace(
            r"\ ",
            r"\s+"
        )

        pattern = (
            r"(?<!\w)"
            + escaped
            + r"(?!\w)"
        )

        sql_keyword_count += len(
            re.findall(pattern, lower_text)
        )

    # 7. XSS-related character count
    xss_symbols = {"<", ">", '"', "'"}

    xss_char_count = sum(
        ch in xss_symbols
        for ch in text
    )

    # 8. Path depth
    path_depth = sum(
        bool(segment)
        for segment in ctx.path_normalized.split("/")
    )

    # 9. Query parameter count
    # Do not URL-decode a second time.
    query_pairs = []

    if ctx.query_normalized:

        for item in ctx.query_normalized.split("&"):

            if not item:
                continue

            key, separator, value = item.partition("=")

            query_pairs.append((
                key,
                value if separator else ""
            ))

    query_param_count = len(query_pairs)

    # 10. Maximum parameter length
    parameter_lengths = [
        len(part)
        for pair in query_pairs
        for part in pair
    ]

    for key, value in ctx.body_fields_normalized.items():
        parameter_lengths.extend([
            len(key),
            len(str(value))
        ])

    max_param_length = max(
        parameter_lengths,
        default=0
    )

    # 11. Non-ASCII character count
    non_ascii_count = sum(
        ord(ch) > 127
        for ch in text
    )

    # 12. URL decode iterations
    decode_iterations = ctx.decode_iterations

    features = np.array(
        [
            payload_length,
            entropy,
            special_char_ratio,
            digit_ratio,
            uppercase_ratio,
            sql_keyword_count,
            xss_char_count,
            path_depth,
            query_param_count,
            max_param_length,
            non_ascii_count,
            decode_iterations
        ],
        dtype=np.float64
    )

    if features.shape != (len(FEATURE_NAMES),):
        raise ValueError("Unexpected feature count")

    if not np.isfinite(features).all():
        raise ValueError("Features contain NaN or infinity")

    return features
