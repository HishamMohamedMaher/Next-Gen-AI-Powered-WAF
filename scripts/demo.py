"""Interactive demonstration script for AI-WAF.

Sends a progressive sequence of requests to illustrate WAF protections:
1. Benign requests (should pass -> 200)
2. Basic SQLi (should block -> 403)
3. Obfuscated SQLi (should block -> 403)
4. XSS (should block -> 403)
5. Path traversal (should block -> 403)
6. Rapid requests (should trigger rate limit -> 429)

Prints colored terminal output highlighting decisions and latencies.
"""

import argparse
import sys
import time
from typing import Optional
import httpx

# ANSI color escape sequences
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"
BOLD = "\033[1m"


def print_step(title: str) -> None:
    """Print demo step separator header."""
    print(f"\n{BOLD}{BLUE}=== {title} ==={RESET}")


def send_test_request(
    client: httpx.Client,
    method: str,
    url: str,
    params: Optional[dict] = None,
    data: Optional[dict] = None,
    expected_status: int = 200,
) -> bool:
    """Send single HTTP request, measure response time, and print colorized result.

    Args:
        client: Synchronous HTTP client instance.
        method: HTTP verb ('GET' or 'POST').
        url: Target URL endpoint.
        params: Query parameters.
        data: JSON or form body data.
        expected_status: Expected HTTP status code (e.g. 200, 403, 429).

    Returns:
        True if response status matches expectation, False otherwise.
    """
    pass


def run_demo(target_url: str) -> None:
    """Execute complete interactive attack and benign traffic demo sequence.

    Args:
        target_url: AI-WAF proxy URL (e.g. http://127.0.0.1:8000).
    """
    pass


def main() -> None:
    """CLI entry point for running live AI-WAF demonstration."""
    parser = argparse.ArgumentParser(description="AI-WAF Live Demonstration")
    parser.add_argument(
        "--url",
        type=str,
        default="http://127.0.0.1:8000",
        help="AI-WAF proxy entrypoint URL",
    )
    args = parser.parse_args()
    run_demo(args.url)


if __name__ == "__main__":
    main()
