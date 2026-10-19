import json
import uuid
from urllib.parse import parse_qs
from starlette.requests import Request
from waf.models import RequestContext

MAX_BODY_SIZE = 1 * 1024 * 1024  # 1 MB

async def build_context(request: Request) -> RequestContext:
    """Build a standardized RequestContext from a Starlette Request object safely."""
    try:
        request_id = str(uuid.uuid4())
        client_ip = request.client.host if request.client and request.client.host else "127.0.0.1"
        method = getattr(request, "method", "GET")
        
        try:
            path = request.url.path
            query_string = request.url.query
        except Exception:
            path = "/"
            query_string = ""

        headers = {k.lower(): v for k, v in request.headers.items()} if hasattr(request, "headers") else {}
        content_type = headers.get("content-type", "")

        body_raw = b""
        try:
            body_raw = await request.body()
        except Exception:
            pass

        if len(body_raw) > MAX_BODY_SIZE:
            body_raw = body_raw[:MAX_BODY_SIZE]

        body_fields = {}
        if body_raw:
            if "application/json" in content_type:
                try:
                    parsed_json = json.loads(body_raw.decode("utf-8", errors="ignore"))
                    if isinstance(parsed_json, dict):
                        body_fields = parsed_json
                except Exception:
                    body_fields = {}
            elif "application/x-www-form-urlencoded" in content_type:
                try:
                    parsed_form = parse_qs(body_raw.decode("utf-8", errors="ignore"))
                    body_fields = {k: v[0] if len(v) == 1 else v for k, v in parsed_form.items()}
                except Exception:
                    body_fields = {}

        return RequestContext(
            request_id=request_id,
            client_ip=client_ip,
            method=method,
            path=path,
            query_string=query_string,
            headers=headers,
            body_raw=body_raw,
            body_fields=body_fields,
            content_type=content_type,
        )
    except Exception:
        # Fallback آمن لضمان عدم إرجاع None أبداً ولتطبيق مبدأ Fail-Open
        return RequestContext(
            request_id=str(uuid.uuid4()),
            client_ip="127.0.0.1",
            method="GET",
            path="/",
            query_string="",
            headers={},
            body_raw=b"",
            body_fields={},
            content_type="",
        )pytest tests/test_context.py -v