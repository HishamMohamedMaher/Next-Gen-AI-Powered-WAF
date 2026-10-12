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
    """Load configuration from a YAML file and initialize the global config.

    Parses YAML configuration parameters, maps them to WAFConfig fields,
    populates defaults for missing keys, and updates the global `_current` instance.

    Args:
        path: Path to the YAML configuration file.

    Returns:
        The newly instantiated and validated immutable WAFConfig instance.

    Raises:
        FileNotFoundError: If the specified configuration file does not exist.
        yaml.YAMLError: If the configuration file contains invalid YAML syntax.
    """
    pass


def get() -> WAFConfig:
    """Retrieve the current active WAF configuration.

    If configuration has not been explicitly loaded via load(), this loads
    from the default configuration path or returns a default instance.

    Returns:
        The active immutable WAFConfig instance.
    """
    pass


def reload(path: Optional[str] = None) -> WAFConfig:
    """Reload the WAF configuration from disk.

    Reloads configuration settings either from the specified path or the
    previously remembered configuration path.

    Args:
        path: Optional path to override the configuration file location.

    Returns:
        The reloaded WAFConfig instance.
    """
    pass
