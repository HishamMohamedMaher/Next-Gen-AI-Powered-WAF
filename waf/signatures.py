"""Deterministic Rule-Based Signature Engine.

This module provides regex-based pattern matching against known attack vectors
(SQL Injection, Cross-Site Scripting, Path Traversal, Command Injection, etc.).
It enforces ReDoS prevention validation prior to compiling rule patterns and supports
paranoia level thresholding.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import logging
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Pattern

from waf.models import AttackType, RequestContext

logger = logging.getLogger("ai_waf.signatures")

# Regular expression pattern to detect potential ReDoS vulnerabilities (e.g., nested quantifiers)
DANGEROUS_PATTERNS: Pattern[str] = re.compile(
    r"(\w+\*|\w+\+|\w+\{\d+,?\d*\})\s*(\*|\+|\{\d+,?\d*\})|\((?:[^()]*\+[^()]*)*\)\+|\((?:[^()]*\*(?:[^()]*))*\)\*"
)


@dataclass
class SignatureHit:
    """Represents a successful signature match detection."""

    rule_id: str
    attack_type: AttackType
    matched_field: str
    matched_pattern: str
    paranoia_level: int


@dataclass
class CompiledRule:
    """Internal representation of a validated and compiled detection rule."""

    rule_id: str
    attack_type: AttackType
    pattern: Pattern[str]
    raw_pattern: str
    paranoia_level: int
    description: str = ""


# Global registry of active, validated, and compiled signature rules
_compiled_rules: List[CompiledRule] = []

_CATEGORY_MAP: Dict[str, AttackType] = {
    "sqli": AttackType.SQLI,
    "sql_injection": AttackType.SQLI,
    "xss": AttackType.XSS,
    "path_traversal": AttackType.PATH_TRAVERSAL,
    "traversal": AttackType.PATH_TRAVERSAL,
    "command_injection": AttackType.COMMAND_INJECTION,
    "cmdi": AttackType.COMMAND_INJECTION,
}


def validate_rule(pattern: str) -> bool:
    """Validate a regular expression for compilation safety and ReDoS susceptibility.

    Checks pattern against dangerous catastrophic backtracking structures
    (such as nested quantifiers) and attempts a test compilation.

    Args:
        pattern: Raw regular expression pattern string.

    Returns:
        True if the pattern is safe and compilable; False otherwise.
    """
    if not pattern or not isinstance(pattern, str):
        return False

    if DANGEROUS_PATTERNS.search(pattern):
        logger.warning("Rejected ReDoS-vulnerable pattern: %s", pattern)
        return False

    try:
        re.compile(pattern)
        return True
    except re.error as exc:
        logger.warning("Rejected invalid regex pattern '%s': %s", pattern, exc)
        return False


def load_rules(path: str = "rules/rules.json") -> int:
    """Load, validate, and compile signature rules from a JSON definition file.

    Populates `_compiled_rules` with rules passing ReDoS safety checks.
    Silently rejects or logs warnings for malformed or unsafe rules.

    Args:
        path: Path to the JSON rules configuration file.

    Returns:
        Number of successfully loaded and compiled rules.

    Raises:
        FileNotFoundError: If the rules file does not exist.
        json.JSONDecodeError: If the rules file is not valid JSON.
    """
    rule_path = Path(path)
    if not rule_path.exists():
        raise FileNotFoundError(f"Rules file not found: {path}")

    with rule_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    rules_list = data.get("rules", []) if isinstance(data, dict) else data
    if not isinstance(rules_list, list):
        return 0

    _compiled_rules.clear()

    for item in rules_list:
        if not isinstance(item, dict):
            continue
        if not item.get("enabled", True):
            continue

        rule_id = str(item.get("id", ""))
        raw_pattern = item.get("pattern", "")
        category_str = str(item.get("category", "")).lower()
        paranoia_level = int(item.get("paranoia_level", 1))
        description = str(item.get("name", item.get("description", "")))

        if not rule_id or not validate_rule(raw_pattern):
            logger.warning("Skipping invalid or unsafe rule: %s", rule_id or raw_pattern)
            continue

        attack_type = _CATEGORY_MAP.get(category_str, AttackType.UNKNOWN)
        compiled_pat = re.compile(raw_pattern, re.IGNORECASE)

        _compiled_rules.append(
            CompiledRule(
                rule_id=rule_id,
                attack_type=attack_type,
                pattern=compiled_pat,
                raw_pattern=raw_pattern,
                paranoia_level=paranoia_level,
                description=description,
            )
        )

    return len(_compiled_rules)


def scan(ctx: RequestContext, paranoia_level: int = 1) -> Optional[SignatureHit]:
    """Scan request context against compiled signature rules.

    Evaluates normalized fields first, followed by original fields, matching
    against request path, query string, and body contents. Matches are filtered
    by paranoia_level (rules with rule.paranoia_level <= paranoia_level).
    Short-circuits upon the first confirmed match.

    Args:
        ctx: Populated RequestContext instance to evaluate.
        paranoia_level: Sensitivity level (1 to 4). Higher values enable stricter rules.

    Returns:
        SignatureHit detailing the match if any rule triggered; None if all rules passed.
    """
    if not _compiled_rules:
        try:
            load_rules()
        except Exception:
            return None

    fields_to_scan: List[tuple[str, str]] = []

    if getattr(ctx, "path_normalized", ""):
        fields_to_scan.append(("path_normalized", ctx.path_normalized))
    if getattr(ctx, "query_normalized", ""):
        fields_to_scan.append(("query_normalized", ctx.query_normalized))
    body_norm = getattr(ctx, "body_fields_normalized", None)
    if isinstance(body_norm, dict):
        for k, v in body_norm.items():
            if v:
                fields_to_scan.append((f"body_normalized.{k}", str(v)))

    if getattr(ctx, "path", ""):
        fields_to_scan.append(("path", ctx.path))
    if getattr(ctx, "query_string", ""):
        fields_to_scan.append(("query", ctx.query_string))
    body_orig = getattr(ctx, "body_fields", None)
    if isinstance(body_orig, dict):
        for k, v in body_orig.items():
            if v is not None and str(v):
                fields_to_scan.append((f"body.{k}", str(v)))
    body_raw = getattr(ctx, "body_raw", b"")
    if body_raw:
        raw_str = (
            body_raw.decode("utf-8", errors="ignore")
            if isinstance(body_raw, bytes)
            else str(body_raw)
        )
        if raw_str:
            fields_to_scan.append(("body_raw", raw_str))

    active_rules = [r for r in _compiled_rules if r.paranoia_level <= paranoia_level]

    for field_name, field_value in fields_to_scan:
        for rule in active_rules:
            if rule.pattern.search(field_value):
                return SignatureHit(
                    rule_id=rule.rule_id,
                    attack_type=rule.attack_type,
                    matched_field=field_name,
                    matched_pattern=rule.raw_pattern,
                    paranoia_level=rule.paranoia_level,
                )

    return None