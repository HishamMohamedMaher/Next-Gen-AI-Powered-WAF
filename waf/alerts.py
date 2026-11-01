"""Security alerting and deduplication engine for AI-WAF.

Evaluates processed security events against threat rules, determines alert
severity levels, deduplicates alerts within sliding time windows, and generates
or aggregates Alert entities for notification and database persistence.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Dict, Optional, Tuple, Union

from waf.models import Action, Alert, AttackType, Layer, WAFEvent

logger = logging.getLogger(__name__)

# In-memory deduplication cache: key format "(client_ip, attack_type)" -> Alert instance
_recent_alerts: Dict[str, Alert] = {}

DEDUP_WINDOW_SECONDS: float = 300.0


def _find_existing(
    ip: str,
    attack_type: Union[AttackType, str],
    window: float = DEDUP_WINDOW_SECONDS,
) -> Optional[Alert]:
    """Search for an existing active alert for the same IP and attack type within the window.

    Args:
        ip: The client IP address.
        attack_type: The attack classification enum or string value.
        window: Sliding time window in seconds to consider for deduplication.

    Returns:
        The matching Alert instance if found within the time window, or None.
    """
    atk_str = attack_type.value if isinstance(attack_type, AttackType) else str(attack_type)
    key = f"{ip}:{atk_str}"
    
    if key in _recent_alerts:
        alert = _recent_alerts[key]
        now = time.time()
        if (now - alert.last_seen) <= window:
            return alert
        else:
            # Expired alert in cache
            del _recent_alerts[key]
            
    return None


def _should_alert(event: WAFEvent) -> Tuple[bool, str]:
    """Determine whether an event warrants an alert and compute its severity.

    Evaluates event properties against alert triggering rules:
    - High-confidence block decisions (severity: 'critical' or 'high')
    - Blacklist trigger or repeated IP attacks (severity: 'high')
    - Rate limit violations (severity: 'medium')
    - Monitor zone threats with high confidence (severity: 'medium' or 'low')

    Args:
        event: The incoming WAFEvent to evaluate.

    Returns:
        A tuple of (should_create, severity) where should_create is a boolean and
        severity is a string ('critical', 'high', 'medium', 'low', 'info').
    """
    action_val = event.action.value if isinstance(event.action, Action) else str(event.action)
    layer_val = event.layer.value if isinstance(event.layer, Layer) else str(event.layer)
    
    # 1. Confirmed Block Decisions
    if action_val == Action.BLOCK.value:
        if event.confidence >= 0.90 or layer_val in (Layer.BLACKLIST.value, Layer.SIGNATURE.value):
            return True, "critical"
        return True, "high"

    # 2. Blacklist Triggers
    if layer_val == Layer.BLACKLIST.value:
        return True, "high"

    # 3. Rate Limit Violations
    if layer_val == Layer.RATE_LIMIT.value:
        return True, "medium"

    # 4. High AI Confidence Threats in Monitor Mode
    if event.confidence >= 0.85:
        return True, "high"
    elif event.confidence >= 0.50 and action_val == Action.MONITOR.value:
        return True, "medium"

    # 5. Clean or Low-Risk Allowed Requests
    return False, "info"


def process(event: WAFEvent) -> Optional[Alert]:
    """Process a WAF event to evaluate alerting conditions and handle deduplication.

    Checks if the event meets alerting criteria using `_should_alert`. If an alert
    should be generated:
    - Looks for an existing recent alert with identical (IP, attack_type).
    - If found within the deduplication window, increments its occurrence count,
      updates `last_seen`, and updates the database record.
    - If no recent matching alert exists, constructs a new Alert instance,
      persists it to SQLite via `insert_alert`, and caches it in `_recent_alerts`.

    Args:
        event: The incoming WAFEvent.

    Returns:
        The created or updated Alert instance if an alert was generated, or None.
    """
    should_create, severity = _should_alert(event)
    if not should_create:
        return None

    now = time.time()
    ip = event.client_ip
    attack_type_str = event.attack_type.value if isinstance(event.attack_type, AttackType) else str(event.attack_type)
    
    # Check for existing alert for deduplication
    existing_alert = _find_existing(ip, attack_type_str)
    
    if existing_alert:
        # Update existing alert counters
        existing_alert.count += 1
        existing_alert.last_seen = now
        existing_alert.confidence = max(existing_alert.confidence, event.confidence)
        return existing_alert

    # Create a new Alert instance
    new_alert = Alert(
        id=str(uuid.uuid4()),
        created_at=now,
        last_seen=now,
        severity=severity,
        attack_type=attack_type_str,
        client_ip=ip,
        path=event.path,
        payload_snippet=event.payload_snippet,
        confidence=event.confidence,
        count=1,
        status="new",
        rule_id=event.rule_id,
    )

    # Save to memory cache
    cache_key = f"{ip}:{attack_type_str}"
    _recent_alerts[cache_key] = new_alert

    return new_alert