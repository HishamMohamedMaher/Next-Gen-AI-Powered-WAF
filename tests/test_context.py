"""Tests for RequestContext builder and parser."""

import pytest
from unittest.mock import AsyncMock, MagicMock
from waf.models import RequestContext


@pytest.mark.asyncio
async def test_build_from_get_request():
    """Verify context creation from an incoming GET HTTP request."""
    # Mocking a FastAPI/Starlette Request
    request = MagicMock()
    request.method = "GET"
    request.url.path = "/api/v1/users"
    request.query_params = {"id": "1", "search": "admin"}
    request.headers = {"user-agent": "pytest-client", "host": "localhost"}
    request.client.host = "127.0.0.1"
    request.body = AsyncMock(return_value=b"")

    ctx = await RequestContext.from_request(request)

    assert ctx.method == "GET"
    assert ctx.path == "/api/v1/users"
    assert ctx.query_params == {"id": "1", "search": "admin"}
    assert ctx.client_ip == "127.0.0.1"


@pytest.mark.asyncio
async def test_build_from_post_json():
    """Verify context creation from a POST request with JSON payload."""
    request = MagicMock()
    request.method = "POST"
    request.url.path = "/login"
    request.headers = {"content-type": "application/json"}
    request.client.host = "192.168.1.50"
    request.body = AsyncMock(return_value=b'{"username": "admin", "password": "123"}')

    ctx = await RequestContext.from_request(request)

    assert ctx.method == "POST"
    assert ctx.body_raw == b'{"username": "admin", "password": "123"}'
    assert ctx.json_payload == {"username": "admin", "password": "123"}


@pytest.mark.asyncio
async def test_build_from_post_form():
    """Verify context creation from a POST request with form URL-encoded payload."""
    request = MagicMock()
    request.method = "POST"
    request.url.path = "/submit"
    request.headers = {"content-type": "application/x-www-form-urlencoded"}
    request.client.host = "10.0.0.5"
    request.body = AsyncMock(return_value=b"field1=value1&field2=value2")

    ctx = await RequestContext.from_request(request)

    assert ctx.method == "POST"
    assert ctx.body_raw == b"field1=value1&field2=value2"


@pytest.mark.asyncio
async def test_invalid_json_body():
    """Verify that malformed or non-parseable JSON body is handled gracefully without crashing."""
    request = MagicMock()
    request.method = "POST"
    request.url.path = "/api/data"
    request.headers = {"content-type": "application/json"}
    request.client.host = "127.0.0.1"
    request.body = AsyncMock(return_value=b'{"bad_json": invalid}')

    ctx = await RequestContext.from_request(request)

    assert ctx.body_raw == b'{"bad_json": invalid}'
    assert ctx.json_payload is None  # Should gracefully handle JSONDecodeError


@pytest.mark.asyncio
async def test_body_size_limit():
    """Verify that context builder respects maximum request body size boundaries."""
    max_size = 100
    oversized_body = b"A" * 150

    request = MagicMock()
    request.method = "POST"
    request.url.path = "/upload"
    request.headers = {"content-type": "application/octet-stream"}
    request.client.host = "127.0.0.1"
    request.body = AsyncMock(return_value=oversized_body)

    ctx = await RequestContext.from_request(request, max_body_size=max_size)

    assert len(ctx.body_raw) <= max_size or ctx.is_body_truncated is True


@pytest.mark.asyncio
async def test_client_ip_extracted():
    """Verify accurate extraction of client IP from headers (e.g. X-Forwarded-For) and socket info."""
    request = MagicMock()
    request.method = "GET"
    request.url.path = "/test"
    request.headers = {"x-forwarded-for": "203.0.113.195, 70.41.3.18"}
    request.client.host = "127.0.0.1"
    request.body = AsyncMock(return_value=b"")

    ctx = await RequestContext.from_request(request)

    # Should extract the real originating IP from X-Forwarded-For
    assert ctx.client_ip == "203.0.113.195"