"""Tests for the token bucket rate limiter module."""

import time
import pytest

from waf.rate_limiter import (
    _buckets,
    _get_limits,
    _is_login_path,
    check,
    cleanup,
)


@pytest.mark.asyncio
async def test_allows_within_limit():
    """Verify that requests under the allowed request rate limit pass through successfully."""
    _buckets.clear()
    ip = "192.168.1.10"
    # الطلبات المتتالية تحت سقف السعة تمر بنجاح
    for _ in range(5):
        assert check(ip, is_login=False) is True


@pytest.mark.asyncio
async def test_blocks_over_limit():
    """Verify that bursts exceeding rate limits trigger rate-limiting response (429 Too Many Requests)."""
    _buckets.clear()
    ip = "192.168.1.20"
    capacity, _ = _get_limits(is_login=False)

    # استهلاك سعة التوكنز بالكامل
    for _ in range(int(capacity)):
        check(ip, is_login=False)

    # الطلب الزائد عن السعة يجب أن يُحظر فوراً
    assert check(ip, is_login=False) is False


@pytest.mark.asyncio
async def test_refill_over_time():
    """Verify that token buckets replenish capacity as time elapses."""
    _buckets.clear()
    ip = "192.168.1.30"
    check(ip, is_login=False)

    # تفريغ رصيد التوكنز تماماً
    _buckets[ip].tokens = 0.0
    assert check(ip, is_login=False) is False

    # محاكاة مرور ثانيتين ونصف (بمعدل 1 توكن/ثانية يُشحن الرصيد مجدداً)
    _buckets[ip].last_refill = time.time() - 2.5
    assert check(ip, is_login=False) is True


@pytest.mark.asyncio
async def test_login_path_stricter_limit():
    """Verify that sensitive paths (such as /rest/user/login) apply stricter rate limit thresholds."""
    _buckets.clear()
    assert _is_login_path("/rest/user/login") is True
    assert _is_login_path("/api/products/search") is False

    ip = "192.168.1.40"
    login_capacity, _ = _get_limits(is_login=True)

    # سقف تسجيل الدخول المشدد هو 5 طلبات فقط
    for _ in range(int(login_capacity)):
        assert check(ip, is_login=True) is True

    # الطلب السادس يُحظر فوراً لحماية مسار المصادقة
    assert check(ip, is_login=True) is False


@pytest.mark.asyncio
async def test_cleanup_removes_old_buckets():
    """Verify that background cleanup routines prune stale or inactive IP buckets to avoid memory leaks."""
    _buckets.clear()
    active_ip = "10.0.0.1"
    stale_ip = "10.0.0.2"

    check(active_ip)
    check(stale_ip)

    # جعل الـ stale_ip خاملاً منذ أكثر من 10 دقائق (700 ثانية)
    _buckets[stale_ip].last_refill = time.time() - 700.0

    purged = cleanup()
    assert purged == 1
    assert active_ip in _buckets
    assert stale_ip not in _buckets


@pytest.mark.asyncio
async def test_different_ips_independent():
    """Verify that rate limits and token buckets are isolated independently per client IP."""
    _buckets.clear()
    ip1 = "172.16.0.1"
    ip2 = "172.16.0.2"

    capacity, _ = _get_limits(is_login=False)
    for _ in range(int(capacity)):
        check(ip1)

    # نفاد رصيد IP1 لا يؤثر إطلاقاً على رصيد IP2 المستقل
    assert check(ip1) is False
    assert check(ip2) is True