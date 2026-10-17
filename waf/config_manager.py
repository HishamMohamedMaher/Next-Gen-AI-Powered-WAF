"""WAF Configuration Manager.

This module provides centralized loading, parsing, and thread-safe access
to runtime configuration options for the AI-WAF system. Configuration is
represented as an immutable dataclass to guarantee safe concurrent reads.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import logging
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
import yaml

logger = logging.getLogger("ai_waf.config")

DEFAULT_STATIC_EXTENSIONS: Tuple[str, ...] = (
    ".css",
    ".js",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
)

DEFAULT_WHITELIST_IPS: Tuple[str, ...] = (
    "127.0.0.1",
    "::1",
)


@dataclass(frozen=True)
class WAFConfig:
    """Immutable runtime configuration container for the AI-WAF engine."""

    mode: str = "block"
    enable_rate_limit: bool = True
    enable_normalizer: bool = True
    enable_signatures: bool = True
    enable_ai: bool = True
    ai_block_threshold: float = 0.85
    ai_monitor_threshold: float = 0.5
    paranoia_level: int = 1
    rate_limit: Dict[str, Any] = field(default_factory=dict)
    blacklist: Dict[str, Any] = field(default_factory=dict)
    abuseipdb: Dict[str, Any] = field(default_factory=dict)
    alerts: Dict[str, Any] = field(default_factory=dict)
    skip_static: bool = True
    static_extensions: Tuple[str, ...] = DEFAULT_STATIC_EXTENSIONS
    whitelist_ips: Tuple[str, ...] = DEFAULT_WHITELIST_IPS
    demo_mode: bool = False
    demo_trusted_ip: str = "127.0.0.1"
    backend_url: str = "http://localhost:8000"
    body_max_size: int = 1_048_576


# Global active configuration instance and last loaded path
_current: Optional[WAFConfig] = None
_current_path: str = "config.yaml"


def load(path: str = "config.yaml") -> WAFConfig:
    """Load configuration from a YAML file and initialize the global config."""
    global _current, _current_path

    config_file = Path(path)
    if not config_file.exists():
        logger.warning(f"Config file not found at {path}, creating default configuration.")
        _current = WAFConfig()
        _current_path = path
        return _current

    try:
        with open(config_file, "r", encoding="utf-8") as f:
            raw_data = yaml.safe_load(f) or {}

        ai_cfg = raw_data.get("ai", {})
        
        # Mapping YAML values to WAFConfig dataclass fields
        config_kwargs = {
            "mode": raw_data.get("mode", "block"),
            "enable_rate_limit": raw_data.get("enable_rate_limit", True),
            "enable_normalizer": raw_data.get("enable_normalizer", True),
            "enable_signatures": raw_data.get("enable_rules", raw_data.get("enable_signatures", True)),
            "enable_ai": raw_data.get("enable_ai", True),
            "ai_block_threshold": ai_cfg.get("threshold_block", 0.85),
            "ai_monitor_threshold": ai_cfg.get("threshold_monitor", 0.5),
            "paranoia_level": raw_data.get("paranoia_level", 1),
            "rate_limit": raw_data.get("rate_limit", {}),
            "blacklist": raw_data.get("blacklist", {}),
            "abuseipdb": raw_data.get("abuseipdb", {}),
            "alerts": raw_data.get("alerts", {}),
            "skip_static": raw_data.get("skip_static", True),
            "static_extensions": tuple(raw_data.get("static_extensions", DEFAULT_STATIC_EXTENSIONS)),
            "whitelist_ips": tuple(raw_data.get("whitelist_ips", DEFAULT_WHITELIST_IPS)),
            "demo_mode": raw_data.get("demo_mode", False),
            "demo_trusted_ip": raw_data.get("demo_trusted_ip", "127.0.0.1"),
            "backend_url": raw_data.get("backend_url", "http://localhost:8000"),
            "body_max_size": raw_data.get("body_max_size", 1_048_576),
        }

        _current = WAFConfig(**config_kwargs)
        _current_path = path
        logger.info(f"Successfully loaded WAF configuration from {path}")
        return _current

    except yaml.YAMLError as e:
        logger.error(f"Failed to parse YAML configuration in {path}: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error loading configuration from {path}: {e}")
        raise


def get() -> WAFConfig:
    """Retrieve the current active WAF configuration."""
    global _current
    if _current is None:
        return load(_current_path)
    return _current


def reload(path: Optional[str] = None) -> WAFConfig:
    """Reload the WAF configuration from disk."""
    global _current_path
    target_path = path if path is not None else _current_path
    return load(target_path)