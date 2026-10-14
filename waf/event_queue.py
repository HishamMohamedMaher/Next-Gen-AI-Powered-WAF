"""Asynchronous event queue and background persistence worker for AI-WAF.

Provides a non-blocking queue interface for dispatching audit events from the
request path and a continuous background worker process that enriches events
with GeoIP metadata, batches database inserts, and triggers security alerts.
"""

from __future__ import annotations

import asyncio
import logging
from typing import List, Optional

from waf import alerts, db, geoip
from waf.models import WAFEvent

logger = logging.getLogger(__name__)

QUEUE_MAX_SIZE: int = 10000
_event_queue: Optional[asyncio.Queue[WAFEvent]] = None
_worker_task: Optional[asyncio.Task] = None


def init_queue() -> None:
    """Initialize the asynchronous event queue."""
    global _event_queue
    _event_queue = asyncio.Queue(maxsize=QUEUE_MAX_SIZE)
    logger.info(f"Event queue initialized with maxsize={QUEUE_MAX_SIZE}.")


def put(event: WAFEvent) -> None:
    """Put a WAFEvent into the queue without blocking the HTTP request path."""
    global _event_queue
    if _event_queue is None:
        init_queue()

    assert _event_queue is not None

    try:
        _event_queue.put_nowait(event)
    except asyncio.QueueFull:
        try:
            _event_queue.get_nowait()
            _event_queue.put_nowait(event)
            logger.warning("Event queue full. Dropped oldest event to accommodate new event.")
        except Exception:
            pass


async def background_writer(batch_size: int = 50, flush_interval: float = 0.5) -> None:
    """Continuous background worker loop consuming events from the queue."""
    global _event_queue
    if _event_queue is None:
        init_queue()

    assert _event_queue is not None
    logger.info("Background writer task started.")

    while True:
        try:
            batch: List[WAFEvent] = []
            start_time = asyncio.get_event_loop().time()

            while len(batch) < batch_size:
                elapsed = asyncio.get_event_loop().time() - start_time
                remaining = flush_interval - elapsed
                if remaining <= 0:
                    break

                try:
                    event = await asyncio.wait_for(_event_queue.get(), timeout=max(0.01, remaining))
                    
                    try:
                        geoip.enrich(event)
                    except Exception as ge:
                        logger.debug(f"GeoIP enrichment skipped or failed: {ge}")

                    batch.append(event)
                    _event_queue.task_done()
                except asyncio.TimeoutError:
                    break

            if batch:
                db.insert_batch(batch)

                for event in batch:
                    try:
                        alerts.process(event)
                    except Exception as ae:
                        logger.error(f"Error processing alert for event {event.request_id}: {ae}")

        except asyncio.CancelledError:
            logger.info("Background writer task cancellation requested.")
            break
        except Exception as e:
            logger.error(f"Unexpected error in background_writer loop: {e}")
            await asyncio.sleep(1.0)


def start_background_writer() -> asyncio.Task:
    """Start the background writer task in the current event loop."""
    global _worker_task
    if _worker_task is None or _worker_task.done():
        _worker_task = asyncio.create_task(background_writer())
        logger.info("Background writer task created and running.")
    return _worker_task


async def stop_background_writer() -> None:
    """Stop the background writer task cleanly and flush remaining queue items."""
    global _worker_task, _event_queue
    if _worker_task and not _worker_task.done():
        _worker_task.cancel()
        try:
            await _worker_task
        except asyncio.CancelledError:
            pass
        _worker_task = None

    if _event_queue and not _event_queue.empty():
        remaining_batch: List[WAFEvent] = []
        while not _event_queue.empty():
            try:
                event = _event_queue.get_nowait()
                remaining_batch.append(event)
                _event_queue.task_done()
            except asyncio.QueueEmpty:
                break
        if remaining_batch:
            db.insert_batch(remaining_batch)

    logger.info("Background writer stopped and queue flushed successfully.")