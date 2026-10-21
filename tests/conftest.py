"""Pytest test configuration and shared fixtures for AI-WAF."""

import asyncio
from typing import AsyncGenerator
import httpx
import pytest

# Example imports matching the AI-WAF project architecture
# Adjust/mock if modules are being loaded dynamically
try:
    from src.config import WAFConfig
    from src.models import RequestContext
    from src.main import app
except ImportError:
    from dataclasses import dataclass, field
    from typing import Dict, Any

    @dataclass
    class WAFConfig:
        """Fallback mock WAFConfig dataclass for tests."""
        backend_url: str = "http://127.0.0.1:3000"
        max_body_size: int = 1048576
        paranoia_level: int = 1
        rate_limit_enabled: bool = True
        ai_detection_enabled: bool = True
        signature_detection_enabled: bool = True
        fail_open: bool = True

    @dataclass
    class RequestContext:
        """Fallback mock RequestContext dataclass for tests."""
        method: str = "GET"
        path: str = "/"
        query_params: Dict[str, str] = field(default_factory=dict)
        headers: Dict[str, str] = field(default_factory=dict)
        client_ip: str = "127.0.0.1"
        body: bytes = b""
        raw_body: str = ""
        normalized_query: Dict[str, str] = field(default_factory=dict)
        normalized_body: str = ""

    app = None

pytest_plugins = ["pytest_asyncio"]


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for each test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def sample_config() -> WAFConfig:
    """Fixture providing a WAFConfig instance with test defaults."""
    return WAFConfig(
        backend_url="http://127.0.0.1:3000",
        max_body_size=1048576,
        paranoia_level=1,
        rate_limit_enabled=True,
        ai_detection_enabled=True,
        signature_detection_enabled=True,
        fail_open=True,
    )


@pytest.fixture
def sample_request_context() -> RequestContext:
    """Fixture providing a benign sample GET RequestContext."""
    return RequestContext(
        method="GET",
        path="/rest/products/search",
        query_params={"q": "apple"},
        headers={"host": "localhost", "user-agent": "test-client"},
        client_ip="192.168.1.100",
        body=b"",
        raw_body="",
        normalized_query={"q": "apple"},
        normalized_body="",
    )


@pytest.fixture
def malicious_context() -> RequestContext:
    """Fixture providing a malicious RequestContext with a SQLi payload in query."""
    return RequestContext(
        method="GET",
        path="/rest/products/search",
        query_params={"q": "' OR 1=1--"},
        headers={"host": "localhost", "user-agent": "sqlmap/1.5"},
        client_ip="192.168.1.200",
        body=b"",
        raw_body="",
        normalized_query={"q": "' or 1=1--"},
        normalized_body="",
    )


@pytest.fixture
async def app_client(sample_config) -> AsyncGenerator[httpx.AsyncClient, None]:
    """Asynchronous HTTP test client fixture wrapping the FastAPI application."""
    if app is not None:
        async with httpx.AsyncClient(app=app, base_url="http://testserver") as client:
            yield client
    else:
        # Fallback dummy transport client
        async with httpx.AsyncClient(base_url="http://testserver") as client:
            yield client