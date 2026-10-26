"""Main Threat Detection Orchestrator and Decision Pipeline."""

from __future__ import annotations

import logging
import time
import hashlib
import collections
from typing import Optional, Set, Tuple

from waf.config_manager import get as get_config
from waf.models import Action, AttackType, DetectionResult, Layer, RequestContext
import waf.ai_engine as ai_engine
import waf.normalizer as normalizer
import waf.rate_limiter as rate_limiter
import waf.signatures as signatures

logger = logging.getLogger("ai_waf.detector")

# Static file extensions loaded from configuration defaults
STATIC_EXTENSIONS: Tuple[str, ...] = (
    ".css", ".js", ".jpg", ".jpeg", ".png", ".gif",
    ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot",
)

# Day 10: LRU Cache Dictionary to save CPU on repeated normalized inputs
_ai_cache = collections.OrderedDict()
MAX_CACHE_SIZE = 10000

def _get_ai_score_lru(payload_hash: str, ctx: RequestContext) -> float:
    """Evaluate AI score using an LRU cache to avoid redundant recalculation."""
    if payload_hash in _ai_cache:
        _ai_cache.move_to_end(payload_hash)
        return _ai_cache[payload_hash]
    
    # Assuming ai_engine.predict() takes the context and returns a float score
    score = ai_engine.predict(ctx) 
    
    _ai_cache[payload_hash] = score
    if len(_ai_cache) > MAX_CACHE_SIZE:
        _ai_cache.popitem(last=False)
    
    return score


def is_static_file(path: str) -> bool:
    """Check if the requested path corresponds to a static web asset."""
    path_lower = path.lower()
    return path_lower.endswith(STATIC_EXTENSIONS)


def detect(ctx: RequestContext) -> DetectionResult:
    """Evaluate an incoming HTTP request through the multi-layer WAF detection pipeline."""
    # Day 11: Start tracking execution latency
    start_time = time.time()

    def finalize(action: Action, layer: Layer, attack_type: AttackType, confidence: float, reason: str) -> DetectionResult:
        """Helper to build DetectionResult with the measured latency."""
        latency_ms = (time.time() - start_time) * 1000.0
        return DetectionResult(
            action=action,
            layer=layer,
            attack_type=attack_type,
            confidence=confidence,
            reason=reason,
            processing_time_ms=latency_ms
        )

    # 1. Whitelist evaluation
    try:
        whitelist = get_config("whitelist_ips", [])
        if whitelist and ctx.client_ip in whitelist:
            return finalize(Action.ALLOW, Layer.NETWORK, AttackType.NONE, 1.0, "IP Whitelisted")
    except Exception:
        logger.exception("Whitelist evaluation failed - failing open")

    # 2. Blacklist evaluation
    try:
        blacklist = get_config("blacklist_ips", [])
        if blacklist and ctx.client_ip in blacklist:
            return finalize(Action.BLOCK, Layer.NETWORK, AttackType.BLACKLIST, 1.0, "IP Blacklisted")
    except Exception:
        logger.exception("Blacklist evaluation failed - failing open")

    # 3. Rate limiter evaluation
    try:
        # Assumes rate_limiter.check returns False if limit is exceeded
        if hasattr(rate_limiter, 'check') and not rate_limiter.check(ctx.client_ip):
            return finalize(Action.BLOCK, Layer.NETWORK, AttackType.RATE_LIMIT, 1.0, "Rate limit exceeded")
    except Exception:
        logger.exception("Rate limiter evaluation failed - failing open")

    # 4. Static asset check (Day 7)
    try:
        if get_config("skip_static", True) and is_static_file(ctx.path):
            return finalize(Action.ALLOW, Layer.STATIC, AttackType.NONE, 1.0, "Static asset bypass")
    except Exception:
        logger.exception("Static asset evaluation failed - failing open")

    # 5. Payload normalization
    try:
        ctx = normalizer.normalize_context(ctx)
    except Exception:
        logger.exception("Payload normalization failed - failing open")

    # 6. Deterministic signature scanning (Day 7)
    try:
        # Assumes signatures.check returns the matched rule name or None
        sig_match = signatures.check(ctx)
        if sig_match:
            return finalize(Action.BLOCK, Layer.SIGNATURE, AttackType.SIGNATURE, 1.0, f"Signature match: {sig_match}")
    except Exception:
        logger.exception("Signature scanning failed - failing open")

    # 7. Machine learning inference with LRU Cache (Days 9 & 10)
    try:
        # Create a deterministic hash from the normalized inputs for the cache
        payload_str = f"{ctx.path}|{ctx.query_string}|{ctx.body_fields}"
        payload_hash = hashlib.sha256(payload_str.encode('utf-8', errors='ignore')).hexdigest()

        ai_score = _get_ai_score_lru(payload_hash, ctx)

        # Apply Thresholds (Day 9)
        monitor_thresh = get_config("ai_monitor_threshold", 0.5)
        block_thresh = get_config("ai_block_threshold", 0.85)

        if ai_score >= block_thresh:
            final_action = Action.BLOCK
        elif ai_score >= monitor_thresh:
            final_action = Action.MONITOR
        else:
            final_action = Action.ALLOW

        return finalize(final_action, Layer.AI, AttackType.ANOMALY, ai_score, f"AI Score: {ai_score:.3f}")
    
    except Exception:
        logger.exception("AI engine inference failed - failing open")

    # Ultimate Fallback (Fail-Open) if everything somehow falls through
    return finalize(Action.ALLOW, Layer.SYSTEM, AttackType.NONE, 0.0, "Pipeline fallthrough (Fail-Open)")