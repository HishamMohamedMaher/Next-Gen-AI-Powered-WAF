"""Performance benchmark script for AI-WAF.

Measures HTTP request latency direct to Juice Shop vs through WAF (benign and malicious).
Calculates percentiles (p50, p95, p99) and exports benchmark results to JSON.
"""

import argparse
import json
import statistics
import time
from pathlib import Path
from typing import Any, Dict, List
import httpx


def run_benchmark_target(url: str, requests_count: int, payload_type: str = "benign") -> Dict[str, Any]:
    """Execute benchmark requests against target URL and compute latency statistics.

    Args:
        url: The endpoint to send requests to.
        requests_count: Number of iterations to execute.
        payload_type: 'benign' or 'malicious' traffic pattern.

    Returns:
        Dictionary containing p50, p95, p99 latencies in milliseconds and status codes.
    """
    pass


def run_full_benchmark(
    direct_url: str,
    waf_url: str,
    requests_count: int,
    output_path: str,
) -> Dict[str, Any]:
    """Run comparative benchmark suite across direct, WAF benign, and WAF malicious paths.

    Args:
        direct_url: Direct backend address (e.g., http://127.0.0.1:3000).
        waf_url: AI-WAF proxy address (e.g., http://127.0.0.1:8000).
        requests_count: Number of requests per scenario.
        output_path: Destination path for JSON report.

    Returns:
        Structured results summary.
    """
    pass


def main() -> None:
    """CLI entry point for running the performance benchmark suite."""
    parser = argparse.ArgumentParser(description="AI-WAF Performance Benchmarking Suite")
    parser.add_argument(
        "--direct-url",
        type=str,
        default="http://127.0.0.1:3000",
        help="Direct Juice Shop backend URL",
    )
    parser.add_argument(
        "--waf-url",
        type=str,
        default="http://127.0.0.1:8000",
        help="AI-WAF proxy entrypoint URL",
    )
    parser.add_argument(
        "--requests",
        type=int,
        default=100,
        help="Number of requests per benchmark case",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="benchmark_results.json",
        help="JSON file output destination",
    )
    args = parser.parse_args()
    run_full_benchmark(args.direct_url, args.waf_url, args.requests, args.output)


if __name__ == "__main__":
    main()
