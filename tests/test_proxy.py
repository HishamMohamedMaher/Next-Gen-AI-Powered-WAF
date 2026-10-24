"""Tests for the reverse proxy forwarding component of AI-WAF."""

import pytest
import httpx
from httpx import ASGITransport
from unittest.mock import patch, AsyncMock

from waf.main import app
from waf.proxy import init_client, close_client

# Setup fixture to ensure the HTTPX client pool is initialized before tests run
@pytest.fixture(autouse=True)
async def setup_proxy():
    await init_client()
    yield
    await close_client()


@pytest.mark.asyncio
async def test_forward_get_request():
    """Verify that a benign GET request passes through and returns status 200."""
    with patch("waf.proxy._client.request", new_callable=AsyncMock) as mock_req:
        mock_req.return_value.status_code = 200
        mock_req.return_value.headers = httpx.Headers({"server": "JuiceShop"})
        mock_req.return_value.content = b"success"

        async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
            response = await client.get("/api/products")

        assert response.status_code == 200
        assert response.content == b"success"
        mock_req.assert_called_once()
        assert mock_req.call_args.kwargs["method"] == "GET"


@pytest.mark.asyncio
async def test_forward_post_with_body():
    """Verify that a POST request with JSON body passes through correctly to the backend."""
    with patch("waf.proxy._client.request", new_callable=AsyncMock) as mock_req:
        mock_req.return_value.status_code = 201
        mock_req.return_value.headers = httpx.Headers({})
        mock_req.return_value.content = b'{"created": true}'

        async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
            response = await client.post("/api/users", json={"username": "test"})

        assert response.status_code == 201
        mock_req.assert_called_once()
        # Updated to match the exact byte string output without spaces
        assert mock_req.call_args.kwargs["content"] == b'{"username":"test"}'


@pytest.mark.asyncio
async def test_body_size_limit():
    """Verify that a request body larger than MAX_BODY_SIZE is truncated or rejected appropriately."""
    async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        headers = {"Content-Length": "2000000"}
        response = await client.post("/api/upload", headers=headers, content=b"a" * 10)

    assert response.status_code == 413
    assert response.json()["detail"] == "Payload Too Large"


@pytest.mark.asyncio
async def test_hop_by_hop_headers_removed():
    """Verify that hop-by-hop headers (Connection, Keep-Alive, Upgrade, etc.) are stripped before forwarding."""
    with patch("waf.proxy._client.request", new_callable=AsyncMock) as mock_req:
        mock_req.return_value.status_code = 200
        mock_req.return_value.headers = httpx.Headers({})
        mock_req.return_value.content = b""

        async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
            headers = {
                "Connection": "keep-alive",
                "Upgrade": "websocket",
                "Custom-Header": "Allowed"
            }
            await client.get("/", headers=headers)

        forwarded_headers = mock_req.call_args.kwargs["headers"]
        assert "connection" not in forwarded_headers
        assert "upgrade" not in forwarded_headers
        assert "custom-header" in forwarded_headers


@pytest.mark.asyncio
async def test_x_forwarded_for_added():
    """Verify that X-Forwarded-For header is correctly appended or created with client IP."""
    with patch("waf.proxy._client.request", new_callable=AsyncMock) as mock_req:
        mock_req.return_value.status_code = 200
        mock_req.return_value.headers = httpx.Headers({})
        mock_req.return_value.content = b""

        async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
            await client.get("/", headers={"X-Forwarded-For": "10.0.0.1"})

        forwarded_headers = mock_req.call_args.kwargs["headers"]
        assert "x-forwarded-for" in forwarded_headers
        assert "10.0.0.1" in forwarded_headers["x-forwarded-for"]
        # Updated to check for the actual mock IP assigned by the transport layer
        assert "127.0.0.1" in forwarded_headers["x-forwarded-for"]


@pytest.mark.asyncio
async def test_backend_down_returns_502():
    """Verify that an unreachable backend service results in a 502 Bad Gateway response."""
    with patch("waf.proxy._client.request", new_callable=AsyncMock) as mock_req:
        mock_req.side_effect = httpx.RequestError("Failed to connect")

        async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
            response = await client.get("/")

        assert response.status_code == 502
        assert "Bad Gateway" in response.text