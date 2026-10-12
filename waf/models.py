"""Data models and core enumerations for the AI-WAF system.

This module defines standard representations for request contexts, detection outcomes,
security events, alerts, and classification categories used across all WAF layers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
import uuid


class Action(str, Enum):
    """Action taken by the WAF on a request."""

    ALLOW = "allow"
    MONITOR = "monitor"
    BLOCK = "block"


class AttackType(str, Enum):
    """Categorization of detected attacks."""

    SQLI = "sqli"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    RATE_LIMIT = "rate_limit"
    BLACKLISTED_IP = "blacklisted_ip"
    UNKNOWN = "unknown"


class Layer(str, Enum):
    """Detection layer responsible for the decision."""

    WHITELIST = "whitelist"
    BLACKLIST = "blacklist"
    RATE_LIMIT = "rate_limit"
    SIGNATURE = "signature"
    AI = "ai"
    NONE = "none"


@dataclass
class RequestContext:
    """Context holding incoming HTTP request details and normalized representations."""

    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    client_ip: str = "127.0.0.1"
    method: str = "GET"
    path: str = "/"
    query_string: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body_raw: bytes = b""
    body_fields: Dict[str, Any] = field(default_factory=dict)
    content_type: str = ""
    path_normalized: str = ""
    query_normalized: str = ""
    body_fields_normalized: Dict[str, Any] = field(default_factory=dict)
    decode_iterations: int = 0
    is_static: bool = False


@dataclass
class DetectionResult:
    """Outcome of threat detection pipeline evaluation."""

    action: Action = Action.ALLOW
    layer: Layer = Layer.NONE
    attack_type: Optional[AttackType] = None
    rule_id: Optional[str] = None
    confidence: float = 0.0
    reason: str = ""
    processing_time_ms: float = 0.0


@dataclass
class WAFEvent:
    """Security audit event captured for analysis, logging, and metrics."""

    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    client_ip: str = "127.0.0.1"
    method: str = "GET"
    path: str = "/"
    payload_snippet: str = ""
    attack_type: Optional[AttackType] = None
    layer: Layer = Layer.NONE
    rule_id: Optional[str] = None
    confidence: float = 0.0
    action: Action = Action.ALLOW
    processing_time_ms: float = 0.0
    country: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None

    @classmethod
    def from_context_and_result(
        cls,
        context: RequestContext,
        result: DetectionResult,
        payload_snippet: str = "",
        country: Optional[str] = None,
        latitude: Optional[float] = None,
        longitude: Optional[float] = None,
    ) -> WAFEvent:
        """Create a WAFEvent directly from RequestContext and DetectionResult."""
        snippet = payload_snippet
        if not snippet:
            if context.query_string:
                snippet = context.query_string[:200]
            elif context.body_raw:
                try:
                    snippet = context.body_raw[:200].decode("utf-8", errors="replace")
                except Exception:
                    snippet = ""

        return cls(
            timestamp=context.timestamp,
            request_id=context.request_id,
            client_ip=context.client_ip,
            method=context.method,
            path=context.path,
            payload_snippet=snippet,
            attack_type=result.attack_type,
            layer=result.layer,
            rule_id=result.rule_id,
            confidence=result.confidence,
            action=result.action,
            processing_time_ms=result.processing_time_ms,
            country=country,
            latitude=latitude,
            longitude=longitude,
        )


@dataclass
class Alert:
    """Aggregated or high-priority security alert generated from WAF events."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    severity: str = "medium"
    attack_type: AttackType = AttackType.UNKNOWN
    client_ip: str = "127.0.0.1"
    path: str = "/"
    payload_snippet: str = ""
    confidence: float = 0.0
    count: int = 1
    status: str = "open"
    rule_id: Optional[str] = None
