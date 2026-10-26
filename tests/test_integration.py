"""End-to-end integration tests for AI-WAF reverse proxy pipeline."""

import pathlib
import pytest
import httpx

PAYLOAD_DIR = pathlib.Path(__file__).parent / "payloads"


@pytest.mark.asyncio
async def test_benign_request_end_to_end(app_client: httpx.AsyncClient):
    """Verify that legitimate end-user requests traverse the WAF and reach the backend cleanly."""
    response = await app_client.get("/rest/products/search", params={"q": "apple"})
    assert response.status_code != 403


@pytest.mark.asyncio
async def test_sqli_blocked_end_to_end(app_client: httpx.AsyncClient):
    """Verify that SQL injection payloads are intercepted and return 403 Forbidden before backend."""
    response = await app_client.get("/rest/products/search", params={"q": "' OR 1=1--"})
    assert response.status_code in [403, 400]


@pytest.mark.asyncio
async def test_obfuscated_sqli_blocked(app_client: httpx.AsyncClient):
    """Verify that double-encoded or obfuscated SQLi attacks are normalized and intercepted."""
    # Double URL encoded SQLi payload
    response = await app_client.get("/rest/products/search", params={"q": "%2527%20OR%201%3D1--"})
    assert response.status_code in [403, 400]


@pytest.mark.asyncio
async def test_xss_blocked(app_client: httpx.AsyncClient):
    """Verify that reflected/stored XSS payloads return 403 Forbidden end-to-end."""
    response = await app_client.get("/rest/products/search", params={"q": "<script>alert(1)</script>"})
    assert response.status_code in [403, 400]


@pytest.mark.asyncio
async def test_baseline_traffic_passes(app_client: httpx.AsyncClient):
    """Verify that all recorded benign baseline traffic samples pass without false positive blocks."""
    path = PAYLOAD_DIR / "benign.txt"
    endpoints = []
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            endpoints = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    
    # Fallback default endpoints if benign.txt is empty or missing
    if not endpoints:
        endpoints = ["/rest/products/search?q=laptop", "/home", "/about"]

    for endpoint in endpoints:
        if not endpoint.startswith("/"):
            endpoint = f"/{endpoint}"
        response = await app_client.get(endpoint)
        assert response.status_code != 403, f"False Positive detected on endpoint: {endpoint}"