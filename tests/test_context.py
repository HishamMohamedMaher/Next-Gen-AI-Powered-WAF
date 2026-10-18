"""Tests for build_context (RequestContext builder)."""

import pytest
from starlette.requests import Request

from waf.context import build_context


def make_request(method="GET", path="/", query="", headers=None,
                 body=b"", client=("127.0.0.1", 50000)):
    """Build a real Starlette Request from a raw ASGI scope."""
    raw_headers = [(k.lower().encode(), v.encode())
                   for k, v in (headers or {}).items()]
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "raw_path": path.encode(),
        "query_string": query.encode(),
        "headers": raw_headers,
        "client": client,
        "server": ("testserver", 80),
        "scheme": "http",
        "http_version": "1.1",
    }

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(scope, receive)


@pytest.mark.asyncio
async def test_build_from_get_request():
    req = make_request(
        path="/api/v1/users",
        query="id=1&search=admin",
        headers={"user-agent": "pytest-client"},
    )
    ctx = await build_context(req)

    assert ctx.method == "GET"
    assert ctx.path == "/api/v1/users"
    assert ctx.query_string == "id=1&search=admin"
    assert ctx.client_ip == "127.0.0.1"
    assert ctx.headers["user-agent"] == "pytest-client"


@pytest.mark.asyncio
async def test_build_from_post_json():
    body = b'{"username": "admin", "password": "123"}'
    req = make_request(
        method="POST", path="/login",
        headers={"content-type": "application/json"}, body=body,
    )
    ctx = await build_context(req)

    assert ctx.body_raw == body
    assert ctx.body_fields == {"username": "admin", "password": "123"}
    assert ctx.content_type.startswith("application/json")


@pytest.mark.asyncio
async def test_build_from_post_form():
    body = b"field1=value1&field2=value2"
    req = make_request(
        method="POST", path="/submit",
        headers={"content-type": "application/x-www-form-urlencoded"},
        body=body,
    )
    ctx = await build_context(req)

    assert ctx.body_raw == body
    assert ctx.body_fields == {"field1": "value1", "field2": "value2"}


@pytest.mark.asyncio
async def test_invalid_json_body():
    # القرار المطلوب من الفريق: يرمي HTTPException ولا يفتح (fail-open)؟
    # هنا بنفترض fail-open: الـ body الخام بيتحفظ والحقول فاضية.
    body = b'{"bad_json": invalid}'
    req = make_request(
        method="POST", path="/api/data",
        headers={"content-type": "application/json"}, body=body,
    )
    ctx = await build_context(req)

    assert ctx.body_raw == body
    assert ctx.body_fields == {}


@pytest.mark.asyncio
async def test_body_size_limit(monkeypatch):
    # الحد في waf.context.MAX_BODY_SIZE، فبنصغّره للاختبار
    monkeypatch.setattr("waf.context.MAX_BODY_SIZE", 100)
    req = make_request(
        method="POST", path="/upload",
        headers={"content-type": "application/octet-stream"},
        body=b"A" * 150,
    )
    ctx = await build_context(req)

    assert len(ctx.body_raw) <= 100


@pytest.mark.asyncio
async def test_client_ip_from_socket():
    req = make_request(path="/test", client=("192.168.1.50", 40000))
    ctx = await build_context(req)

    assert ctx.client_ip == "192.168.1.50"


@pytest.mark.asyncio
async def test_request_id_is_unique():
    ctx1 = await build_context(make_request())
    ctx2 = await build_context(make_request())

    assert ctx1.request_id
    assert ctx1.request_id != ctx2.request_id