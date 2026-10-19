"""Tests for the payload and context normalization engine."""

import pytest
from dataclasses import field

from waf.models import RequestContext
from waf.normalizer import (
    MAX_DECODE_ITERATIONS,
    _decode_html_entities,
    _extract_mysql_conditional_comments,
    _iterative_url_decode,
    _normalize_unicode,
    _strip_sql_comments,
    _strip_null_bytes_and_whitespace,
    _to_lowercase,
    normalize_context,
    normalize_text,
)


def test_url_decode_single():
    """Verify single URL decoding: %27 becomes '."""
    decoded, iters = _iterative_url_decode("%27")
    assert decoded == "'"
    assert iters == 1


def test_url_decode_double():
    """Verify recursive URL decoding: %2527 becomes '."""
    decoded, iters = _iterative_url_decode("%2527")
    assert decoded == "'"
    assert iters == 2


def test_url_decode_triple():
    """Verify triple URL decoding: %252527 becomes '."""
    decoded, iters = _iterative_url_decode("%252527")
    assert decoded == "'"
    assert iters == 3


def test_url_decode_max_iterations():
    """Verify that recursive decoding halts at MAX_DECODE_ITERATIONS to prevent infinite loops."""
    six_times_encoded = "%252525252527"
    decoded, iters = _iterative_url_decode(six_times_encoded, MAX_DECODE_ITERATIONS)
    assert iters == MAX_DECODE_ITERATIONS
    assert decoded == "%27"


def test_html_entity_decode():
    """Verify HTML entity decoding: &lt; becomes <."""
    assert _decode_html_entities("&lt;") == "<"
    assert _decode_html_entities("&gt;") == ">"
    assert _decode_html_entities("&#39;") == "'"
    assert _decode_html_entities("&#x27;") == "'"


def test_unicode_nfkc():
    """Verify Unicode NFKC normalization converts fullwidth/compatibility characters."""
    assert _normalize_unicode("\uff1c") == "<"
    assert _normalize_unicode("\uff1e") == ">"
    assert _normalize_unicode("\uff07") == "'"


def test_null_byte_removal():
    """Verify that null bytes (\\x00) are stripped from the payload."""
    assert _strip_null_bytes_and_whitespace("file.png\x00.php") == "file.png.php"
    assert _strip_null_bytes_and_whitespace("test%00") == "test"
    assert _strip_null_bytes_and_whitespace("test\\0") == "test"


def test_sql_comment_to_space():
    """Verify SQL inline comment replacement: /**/ becomes whitespace."""
    assert _strip_sql_comments("SELECT/**/1") == "SELECT 1"
    assert _strip_sql_comments("UNION/*comment*/SELECT") == "UNION SELECT"


def test_conditional_comment_extract():
    """Verify MySQL conditional comment extraction: /*!50000SELECT*/ becomes SELECT."""
    assert _extract_mysql_conditional_comments("/*!50000SELECT*/") == "SELECT"
    assert _extract_mysql_conditional_comments("/*!SELECT*/") == "SELECT"


def test_lowercase():
    """Verify case normalization converts uppercase keywords like UNION to lowercase union."""
    assert _to_lowercase("UNION") == "union"
    assert _to_lowercase("SeLeCt") == "select"


def test_decode_iterations_count():
    """Verify that the engine accurately counts the number of decoding iterations performed."""
    res = normalize_text("%2527")
    assert res.decode_iterations == 2
    assert res.normalized == "'"


def test_normalize_context():
    """Verify that an entire RequestContext (path, params, headers, body) is normalized."""
    ctx = RequestContext(
        request_id="req-1",
        timestamp=1.0,
        client_ip="127.0.0.1",
        method="GET",
        path="/api/%252e%252e/search",
        query_string="q=%2527/**/OR/**/1=1",
        headers={"content-type": "application/json"},
        body_raw=b"",
        body_fields={"username": "&lt;admin&gt;", "id": 1},
        content_type="application/json",
    )
    norm_ctx = normalize_context(ctx)
    assert norm_ctx.path_normalized == "/api/../search"
    assert norm_ctx.query_normalized == "q=' or 1=1"
    assert norm_ctx.body_fields_normalized["username"] == "<admin>"
    assert norm_ctx.body_fields_normalized["id"] == "1"
    assert norm_ctx.decode_iterations == 2


def test_empty_string():
    """Verify that normalizing an empty string safely returns an empty string."""
    res = normalize_text("")
    assert res.normalized == ""
    assert res.decode_iterations == 0


def test_already_clean():
    """Verify that benign, clean text passes through normalization without unexpected mutation."""
    clean_text = "clean normal text 123"
    res = normalize_text(clean_text)
    assert res.normalized == clean_text
    assert res.decode_iterations == 0


'''
before first run : pip install pytest-asyncio
to run tests : pytest tests/test_normalizer.py -v
'''