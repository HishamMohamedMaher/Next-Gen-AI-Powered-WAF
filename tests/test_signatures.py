"""Tests for the regex signature inspection engine."""

import pytest

from waf.models import AttackType, RequestContext
from waf.signatures import load_rules, scan, validate_rule


def _build_ctx(
    path: str = "/",
    query: str = "",
    body_fields: dict | None = None,
    path_norm: str = "",
    query_norm: str = "",
    body_norm: dict | None = None,
) -> RequestContext:
    """Helper to build a RequestContext for signature unit tests."""
    return RequestContext(
        request_id="req-sig-test",
        timestamp=1.0,
        client_ip="127.0.0.1",
        method="GET",
        path=path,
        query_string=query,
        headers={"host": "localhost"},
        body_raw=b"",
        body_fields=body_fields or {},
        content_type="application/json",
        path_normalized=path_norm,
        query_normalized=query_norm,
        body_fields_normalized=body_norm or {},
    )


def test_sqli_basic():
    """Verify detection of classic SQL injection payloads like `' OR 1=1`."""
    load_rules()
    ctx = _build_ctx(query="q=' OR 1=1--", query_norm="q=' or 1=1--")
    hit = scan(ctx, paranoia_level=1)
    assert hit is not None
    assert hit.attack_type == AttackType.SQLI
    assert hit.rule_id == "SQLI-001"


def test_sqli_union():
    """Verify detection of UNION-based SQL injection payloads like `UNION SELECT`."""
    load_rules()
    payload = "id=1 UNION SELECT username, password FROM users"
    ctx = _build_ctx(query=payload, query_norm=payload.lower())
    hit = scan(ctx, paranoia_level=1)
    assert hit is not None
    assert hit.attack_type == AttackType.SQLI
    assert hit.rule_id == "SQLI-002"


def test_xss_script_tag():
    """Verify detection of script tag Cross-Site Scripting payloads like `<script>`."""
    load_rules()
    tag = "<" + "script>evil()</" + "script>"
    ctx = _build_ctx(query=f"q={tag}", query_norm=f"q={tag}")
    hit = scan(ctx, paranoia_level=1)
    assert hit is not None
    assert hit.attack_type == AttackType.XSS
    assert hit.rule_id == "XSS-001"


def test_xss_event_handler():
    """Verify detection of HTML event handler XSS vectors like `onerror=`."""
    load_rules()
    vec = "<img src=x on" + "error=1>"
    ctx = _build_ctx(body_fields={"comment": vec}, body_norm={"comment": vec})
    hit = scan(ctx, paranoia_level=1)
    assert hit is not None
    assert hit.attack_type == AttackType.XSS
    assert hit.rule_id == "XSS-002"


def test_path_traversal():
    """Verify detection of directory traversal patterns like `../../etc/passwd`."""
    load_rules()
    trav = "/files/../../etc/" + "passwd"
    ctx = _build_ctx(path=trav, path_norm=trav)
    hit = scan(ctx, paranoia_level=1)
    assert hit is not None
    assert hit.attack_type == AttackType.PATH_TRAVERSAL


def test_cmdi_semicolon():
    """Verify detection of command injection chained with semicolons like `; ls`."""
    load_rules()
    ctx = _build_ctx(query="host=127.0.0.1; ls -la", query_norm="host=127.0.0.1; ls -la")
    hit = scan(ctx, paranoia_level=1)
    assert hit is not None
    assert hit.attack_type == AttackType.COMMAND_INJECTION
    assert hit.rule_id == "CMDI-001"


def test_benign_request_passes():
    """Verify that harmless, everyday user input passes without triggering signatures."""
    load_rules()
    ctx = _build_ctx(
        path="/rest/products/search",
        query="q=organic apple juice 100%",
        body_fields={"customer": "O'Brien", "amount": "$9.99"},
        path_norm="/rest/products/search",
        query_norm="q=organic apple juice 100%",
        body_norm={"customer": "o'brien", "amount": "$9.99"},
    )
    hit = scan(ctx, paranoia_level=1)
    assert hit is None


def test_short_circuit():
    """Verify that evaluation short-circuits on the first critical match to save processing time."""
    load_rules()
    ctx = _build_ctx(query_norm="q=' or 1=1 union select 1")
    hit = scan(ctx, paranoia_level=1)
    assert hit is not None
    assert hit.rule_id == "SQLI-001"


def test_paranoia_levels():
    """Verify that increasing paranoia levels activates additional, stricter rules."""
    load_rules()
    # SQLI-006 (Hex 0x...) is paranoia_level=2; XSS-007 (expression(...)) is paranoia_level=3
    ctx_l2 = _build_ctx(query="val=0x41424344", query_norm="val=0x41424344")
    assert scan(ctx_l2, paranoia_level=1) is None
    hit_l2 = scan(ctx_l2, paranoia_level=2)
    assert hit_l2 is not None
    assert hit_l2.rule_id == "SQLI-006"

    ctx_l3 = _build_ctx(query="css=expression(1)", query_norm="css=expression(1)")
    assert scan(ctx_l3, paranoia_level=2) is None
    hit_l3 = scan(ctx_l3, paranoia_level=3)
    assert hit_l3 is not None
    assert hit_l3.rule_id == "XSS-007"


def test_redos_protection():
    """Verify that rule validation rejects regex patterns prone to Regular Expression Denial of Service (ReDoS)."""
    assert validate_rule(r"(a+)+") is False
    assert validate_rule(r"([a-z]+)+") is False
    assert validate_rule(r"(.*)*") is False
    assert validate_rule(r"[unclosed") is False
    assert validate_rule(r"(?i)\bunion\s+select\b") is True


def test_scan_normalized_and_original():
    """Verify that signatures inspect both raw inputs and normalized representations."""
    load_rules()
    # 1. هجمة مشوهة تظهر فقط بعد التطبيع في query_normalized
    ctx_norm = _build_ctx(query="q=%2527%2520OR%25201=1", query_norm="q=' or 1=1")
    hit_norm = scan(ctx_norm, paranoia_level=1)
    assert hit_norm is not None
    assert hit_norm.matched_field == "query_normalized"

    # 2. هجمة Null Byte (%00) مسحها الـ Normalizer من النسخة المطبّعة لكنها تُكتشف في النسخة الخام عبر TRAV-005
    ctx_raw = _build_ctx(query="file=report.pdf%00.txt", query_norm="file=report.pdf.txt")
    hit_raw = scan(ctx_raw, paranoia_level=1)
    assert hit_raw is not None
    assert hit_raw.rule_id == "TRAV-005"
    assert hit_raw.matched_field == "query"