"""Baseline traffic generator script for AI-WAF.

Generates realistic benign traffic scenarios against Juice Shop or target backend
and logs the request/response payloads to a JSON lines file for ML training and baselining.
"""

import argparse
import json
import os
import sys
from datetime import datetime
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


def generate(base_url: str, output_dir: str) -> None:
    """Run baseline scenarios against base_url and record output to JSON lines file.

    Args:
        base_url: The target server base URL (e.g. http://localhost:3000).
        output_dir: Directory where output log files will be saved.
    """
    pass


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
    args = parser.parse_args()
    generate(args.base_url, args.output_dir)


if __name__ == "__main__":
    main()
