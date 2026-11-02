"""Token Bucket Rate Limiting Engine.

This module enforces in-memory rate limiting using the Token Bucket algorithm,
applying distinct limits for regular traffic versus sensitive login endpoints.
Provides automatic bucket refill and stale bucket eviction mechanisms.
"""

from __future__ import annotations

from dataclasses import dataclass
import logging
import time
from typing import Dict, Optional, Tuple

logger = logging.getLogger("ai_waf.rate_limiter")

# Default capacities and refill rates (tokens per second)
DEFAULT_REGULAR_CAPACITY: float = 60.0
DEFAULT_REGULAR_REFILL_RATE: float = 1.0  # 60 requests per minute

DEFAULT_LOGIN_CAPACITY: float = 5.0
DEFAULT_LOGIN_REFILL_RATE: float = 5.0 / 60.0  # 5 requests per minute

STALE_BUCKET_TIMEOUT: float = 600.0  # 10 minutes in seconds


@dataclass
class Bucket:
    """Represents a token bucket tracking capacity and refill state for a client IP."""

    tokens: float
    last_refill: float


# In-memory mapping of client IP addresses to their respective token buckets
_buckets: Dict[str, Bucket] = {}


def _get_limits(is_login: bool = False) -> Tuple[float, float]:
    """Retrieve capacity and refill rate from config if available, otherwise defaults."""
    capacity = DEFAULT_LOGIN_CAPACITY if is_login else DEFAULT_REGULAR_CAPACITY
    rate = DEFAULT_LOGIN_REFILL_RATE if is_login else DEFAULT_REGULAR_REFILL_RATE

    try:
        from waf.config_manager import get_config

        cfg = get_config()
        if cfg and hasattr(cfg, "rate_limit"):
            rl = cfg.rate_limit
            if is_login:
                login_rpm = getattr(rl, "login_requests_per_minute", None) or getattr(rl, "login_rpm", None)
                if login_rpm is not None:
                    capacity = float(login_rpm)
                    rate = float(login_rpm) / 60.0
            else:
                rpm = getattr(rl, "requests_per_minute", None) or getattr(rl, "requests_per_window", None)
                burst = getattr(rl, "burst", None) or getattr(rl, "capacity", None)
                if burst is not None:
                    capacity = float(burst)
                elif rpm is not None:
                    capacity = float(rpm)
                if rpm is not None:
                    rate = float(rpm) / 60.0
    except Exception:
        pass

    return capacity, rate


def _is_login_path(path: str) -> bool:
    """Determine whether an HTTP request path corresponds to an authentication endpoint.

    Inspects common login keywords (e.g. /login, /signin, /auth, /token) in the path.

    Args:
        path: HTTP request URL path.

    Returns:
        True if the path is an authentication endpoint; False otherwise.
    """
    if not path:
        return False

    path_lower = path.lower()
    login_keywords = ("/login", "/signin", "/auth", "/token", "rest/user/login")
    return any(keyword in path_lower for keyword in login_keywords)


def check(ip: str, is_login: bool = False) -> bool:
    """Evaluate whether an incoming client request conforms to token bucket limits.

    Refills tokens based on elapsed time since `last_refill` up to maximum bucket capacity.
    Deducts one token if available. Supports tighter constraints for login requests.

    Args:
        ip: Client IPv4 or IPv6 address string.
        is_login: True if the request targets an authentication route.

    Returns:
        True if the request is permitted (token available);
        False if rate limit has been exceeded (bucket empty).
    """
    if not ip:
        return False

    capacity, refill_rate = _get_limits(is_login)
    bucket_key = f"{ip}:login" if is_login else ip
    now = time.time()

    if bucket_key not in _buckets:
        _buckets[bucket_key] = Bucket(tokens=capacity, last_refill=now)

    bucket = _buckets[bucket_key]

    # حساب التوكنز الجديدة بناءً على الوقت المنقضي
    elapsed = max(0.0, now - bucket.last_refill)
    bucket.tokens = min(capacity, bucket.tokens + (elapsed * refill_rate))
    bucket.last_refill = now

    # خصم توكن لو متاح
    if bucket.tokens >= 1.0:
        bucket.tokens -= 1.0
        return True

    logger.warning("Rate limit exceeded for IP: %s (login=%s)", ip, is_login)
    return False


def cleanup() -> int:
    """Evict stale token buckets that have been inactive for 10 or more minutes.

    Prevents unbounded memory growth in long-running WAF server instances.

    Returns:
        Number of expired buckets purged from memory.
    """
    now = time.time()
    stale_keys = [
        key for key, bucket in _buckets.items()
        if (now - bucket.last_refill) >= STALE_BUCKET_TIMEOUT
    ]

    for key in stale_keys:
        del _buckets[key]

    if stale_keys:
        logger.info("Purged %d stale rate limit buckets", len(stale_keys))

    return len(stale_keys)