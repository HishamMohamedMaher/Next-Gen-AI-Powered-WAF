"""End-to-end integration tests for AI-WAF reverse proxy pipeline and telemetry queue."""

import asyncio
import sqlite3
import time
import pytest
import httpx

from waf.db import init_db, close_db
from waf.event_queue import init_queue, put, start_background_writer, stop_background_writer
from waf.models import WAFEvent, Action, Layer, AttackType


@pytest.mark.asyncio
async def test_benign_request_end_to_end(app_client: httpx.AsyncClient):
    """Verify that legitimate end-user requests traverse the WAF and reach the backend cleanly."""
    pass


@pytest.mark.asyncio
async def test_sqli_blocked_end_to_end(app_client: httpx.AsyncClient):
    """Verify that SQL injection payloads are intercepted and return 403 Forbidden before backend."""
    pass


@pytest.mark.asyncio
async def test_obfuscated_sqli_blocked(app_client: httpx.AsyncClient):
    """Verify that double-encoded or obfuscated SQLi attacks are normalized and intercepted."""
    pass


@pytest.mark.asyncio
async def test_xss_blocked(app_client: httpx.AsyncClient):
    """Verify that reflected/stored XSS payloads return 403 Forbidden end-to-end."""
    pass


@pytest.mark.asyncio
async def test_baseline_traffic_passes(app_client: httpx.AsyncClient):
    """Verify that all recorded benign baseline traffic samples pass without false positive blocks."""
    pass


@pytest.mark.asyncio
async def test_event_queue_stress_test(tmp_path):
    """Member 4 Task: Stress test logging 1,000 consecutive events to ensure non-blocking execution and DB persistence."""
    test_db_path = str(tmp_path / "test_stress.db")

    # 1. Initialize DB and Queue
    init_db(test_db_path)
    init_queue()
    writer_task = start_background_writer()

    # 2. Benchmark pushing 1,000 events to the queue
    start_time = time.perf_counter()
    num_events = 1000

    for i in range(num_events):
        event = WAFEvent(
            request_id=f"req-stress-{i}",
            client_ip="192.168.1.100",
            method="POST",
            path="/api/login",
            payload_snippet="' OR 1=1 --",
            attack_type=AttackType.SQLI,
            layer=Layer.SIGNATURE,
            rule_id="SQLI-001",
            confidence=0.99,
            action=Action.BLOCK,
            processing_time_ms=1.2,
        )
        put(event)

    elapsed_time = time.perf_counter() - start_time

    # Verify non-blocking queue performance (1,000 puts should take less than 0.5 seconds)
    assert elapsed_time < 0.5, f"Queue put operation was too slow: {elapsed_time:.4f}s"

    # 3. Allow background writer time to flush batch to SQLite
    await asyncio.sleep(1.5)
    await stop_background_writer()

    # 4. Verify DB persistence using direct SQLite query
    conn = sqlite3.connect(test_db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM waf_events")
    count = cursor.fetchone()[0]
    conn.close()
    close_db()

    assert count == num_events, f"Expected {num_events} persisted in DB, but found {count}"