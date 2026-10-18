"""Baseline traffic generator script for AI-WAF.

Generates realistic benign traffic scenarios against Juice Shop or target backend
and logs the request/response payloads to a JSON lines file for ML training
and baselining.
"""

import argparse
import json
import random
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx

SCENARIOS: List[Tuple[str, str, Optional[Dict[str, Any]], str]] = [
    ("GET", "/", None, "Browse homepage"),
    ("GET", "/rest/products/search?q=apple", None, "Search products with keyword 'apple'"),
    ("GET", "/rest/products/search?q=orange", None, "Search products with keyword 'orange'"),
    ("GET", "/api/Quantitys/", None, "Query product quantities"),
    ("GET", "/rest/products/1", None, "View specific product details"),
    ("POST", "/rest/user/login", {"email": "user@example.com", "password": "User123456!"}, "Attempt user login"),
    ("GET", "/rest/basket/1", None, "View basket contents"),
    ("POST", "/api/BasketItems/", {"ProductId": 1, "BasketId": "1", "quantity": 1}, "Add item to cart"),
    ("POST", "/rest/basket/1/checkout", {"coupon": "OFF5"}, "Checkout basket"),
    ("GET", "/assets/public/favicon_js.ico", None, "Request static asset"),
]

BASELINE_FILENAME = "baseline_traffic.jsonl"
BENIGN_FILE = Path(__file__).resolve().parent.parent / "tests" / "payloads" / "benign.txt"
RECORDED_HEADERS = ("user-agent", "content-type")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) Mobile Safari/604.1",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
]
SEARCH_TERMS = ["apple", "juice", "banana", "lemon", "orange", "green", "melon", "carrot"]


def _load_benign_inputs() -> List[str]:
    """Read tests/payloads/benign.txt (one benign input per line)."""
    if not BENIGN_FILE.exists():
        return []
    with open(BENIGN_FILE, encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def _send(
    client: httpx.Client,
    out,
    stats: Counter,
    session_id: str,
    scenario: str,
    method: str,
    path: str,
    body: Optional[Dict[str, Any]] = None,
    params: Optional[Dict[str, str]] = None,
    token: Optional[str] = None,
) -> Optional[httpx.Response]:
    """Send one request, write one JSONL record, and return the response."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    request = client.build_request(method, path, params=params, json=body, headers=headers)

    started = time.perf_counter()
    try:
        response: Optional[httpx.Response] = client.send(request)
    except httpx.HTTPError:
        response = None
    latency_ms = round((time.perf_counter() - started) * 1000, 2)

    status_code = response.status_code if response is not None else 0
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "scenario": scenario,
        "method": request.method,
        "path": request.url.path,
        "query_string": request.url.query.decode("ascii"),
        "headers": {k: v for k, v in request.headers.items() if k.lower() in RECORDED_HEADERS},
        "body": request.content.decode("utf-8", errors="replace"),
        "status_code": status_code,
        "latency_ms": latency_ms,
    }
    out.write(json.dumps(record, ensure_ascii=False) + "\n")
    stats[status_code] += 1
    time.sleep(random.uniform(0.02, 0.15))
    return response


def _run_session(client: httpx.Client, out, stats: Counter, benign_inputs: List[str]) -> None:
    """Simulate one realistic shopper: browse, search, register, login, cart, checkout."""
    sid = uuid.uuid4().hex[:8]

    def call(scenario, method, path, body=None, params=None, token=None):
        return _send(client, out, stats, sid, scenario, method, path, body, params, token)

    call("browse", "GET", "/")
    call("browse", "GET", "/api/Products")
    for term in random.sample(SEARCH_TERMS, 2):
        call("search", "GET", "/rest/products/search", params={"q": term})
    for text in random.sample(benign_inputs, min(2, len(benign_inputs))):
        call("search_benign_input", "GET", "/rest/products/search", params={"q": text})
    product_id = random.randint(1, 10)
    call("product", "GET", f"/api/Products/{product_id}")

    email = f"user_{sid}@example.com"
    password = "Test1234!"
    call("register", "POST", "/api/Users",
         body={"email": email, "password": password, "passwordRepeat": password})
    
    response = call("login", "POST", "/rest/user/login",
                    body={"email": email, "password": password})
    
    # حماية آمنة للتعامل مع الاستجابة وتفادي أخطاء NoneType و JSON
    if response is None or response.status_code != 200:
        return
    try:
        json_data = response.json()
        if not json_data:
            return
        auth = json_data.get("authentication", {})
    except (ValueError, AttributeError):
        return

    token, basket_id = auth.get("token"), auth.get("bid")
    if not token or not basket_id:
        return

    call("cart", "POST", "/api/BasketItems/",
         body={"ProductId": product_id, "BasketId": str(basket_id), "quantity": 1}, token=token)
    call("cart", "GET", f"/rest/basket/{basket_id}", token=token)
    call("checkout", "POST", f"/rest/basket/{basket_id}/checkout", body={}, token=token)


def generate(base_url: str, output_dir: str, sessions: int = 25) -> None:
    """Run baseline scenarios against base_url and record output to JSON lines file."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / BASELINE_FILENAME

    benign_inputs = _load_benign_inputs()
    stats: Counter = Counter()
    random.seed(42)

    with open(out_file, "w", encoding="utf-8") as out:
        with httpx.Client(base_url=base_url, timeout=10.0) as client:
            for method, path, body, description in SCENARIOS:
                _send(client, out, stats, "static00", description, method, path, body)

            for i in range(sessions):
                client.headers["User-Agent"] = random.choice(USER_AGENTS)
                _run_session(client, out, stats, benign_inputs)
                print(f"session {i + 1}/{sessions} done")

    total = sum(stats.values())
    print(f"Saved {total} requests to {out_file}")
    print("Status codes:", dict(sorted(stats.items())))
    if stats.get(0):
        print(f"WARNING: {stats[0]} requests failed to connect. Is the target running at {base_url}?")


def main() -> None:
    """Parse command line arguments and execute baseline traffic generation."""
    parser = argparse.ArgumentParser(description="Generate benign baseline traffic for AI-WAF.")
    parser.add_argument(
        "--base-url",
        type=str,
        default="http://127.0.0.1:3000",
        help="Base URL of target service or WAF proxy",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="data/baseline",
        help="Directory to store baseline JSON lines log",
    )
    parser.add_argument(
        "--sessions",
        type=int,
        default=25,
        help="Number of simulated shopper sessions",
    )
    args = parser.parse_args()
    generate(args.base_url, args.output_dir, args.sessions)


if __name__ == "__main__":
    main()