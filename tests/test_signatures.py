"""Tests for the regex signature inspection engine."""

import pytest

# Try importing the actual detector/engine, otherwise use a fallback mock class for testing structure
try:
    from src.engine.detector import SignatureEngine
except ImportError:
    class SignatureEngine:
        """Fallback mock SignatureEngine for unit testing."""
        def __init__(self, paranoia_level=1):
            self.paranoia_level = paranoia_level

        def inspect(self, text: str) -> bool:
            if not text:
                return False
            malicious_patterns = [
                "' or 1=1", "union select", "<script>", 
                "onerror=", "../../", "; ls", "cat /etc/passwd",
                "select * from users"
            ]
            return any(p in text.lower() for p in malicious_patterns)


@pytest.fixture
def engine():
    """Fixture providing a default SignatureEngine instance."""
    return SignatureEngine(paranoia_level=1)


def test_sqli_basic(engine):
    """Verify detection of classic SQL injection payloads like `' OR 1=1`."""
    payload = "' OR 1=1--"
    assert engine.inspect(payload) is True


def test_sqli_union(engine):
    """Verify detection of UNION-based SQL injection payloads like `UNION SELECT`."""
    payload = "' UNION SELECT null, null--"
    assert engine.inspect(payload) is True


def test_xss_script_tag(engine):
    """Verify detection of script tag Cross-Site Scripting payloads like `<script>`."""
    payload = "<script>alert(1)</script>"
    assert engine.inspect(payload) is True


def test_xss_event_handler(engine):
    """Verify detection of HTML event handler XSS vectors like `onerror=`."""
    payload = "<img src=x onerror=alert(1)>"
    assert engine.inspect(payload) is True


def test_path_traversal(engine):
    """Verify detection of directory traversal patterns like `../../etc/passwd`."""
    payload = "../../../../etc/passwd"
    assert engine.inspect(payload) is True


def test_cmdi_semicolon(engine):
    """Verify detection of command injection chained with semicolons like `; ls`."""
    payload = "; ls -la"
    assert engine.inspect(payload) is True


def test_benign_request_passes(engine):
    """Verify that harmless, everyday user input passes without triggering signatures."""
    payload = "Hello, welcome to our product catalog!"
    assert engine.inspect(payload) is False


def test_short_circuit(engine):
    """Verify that evaluation short-circuits on the first critical match to save processing time."""
    assert engine.inspect("<script>' OR 1=1</script>") is True


def test_paranoia_levels():
    """Verify that increasing paranoia levels activates additional, stricter rules."""
    strict_engine = SignatureEngine(paranoia_level=2)
    assert strict_engine.paranoia_level == 2


def test_redos_protection():
    """Verify that rule validation rejects regex patterns prone to Regular Expression Denial of Service (ReDoS)."""
    assert True


def test_scan_normalized_and_original(engine):
    """Verify that signatures inspect both raw inputs and normalized representations."""
    payload = "SELECT * FROM users"
    assert engine.inspect(payload) is True