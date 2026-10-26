"""Tests for the multi-tiered detection pipeline."""

import pytest
from unittest.mock import patch, MagicMock
from waf.models import RequestContext, Action, Layer, AttackType
from waf.detector import detect

@pytest.fixture
def dummy_context():
    """Create a standard request context for testing."""
    return RequestContext(
        client_ip="192.168.1.1",
        method="GET",
        path="/api/data",
        query_string="",
        headers={"host": "localhost"},
        body_raw=b"",
        body_fields={}
    )

@pytest.fixture
def mock_config():
    config = MagicMock()
    config.whitelist_ips = []
    config.blacklist_ips = []
    config.skip_static = True
    config.ai_monitor_threshold = 0.5
    config.ai_block_threshold = 0.85
    return config

@pytest.fixture(autouse=True)
def mock_rate_limiter():
    """Bypass the real rate limiter so it doesn't block the dummy IPs."""
    with patch("waf.rate_limiter.check", return_value=True) as mock:
        yield mock

@pytest.mark.asyncio
@patch("waf.detector.get_config")
async def test_whitelist_allows(mock_get_config, dummy_context, mock_config):
    mock_config.whitelist_ips = ["192.168.1.1"]
    mock_get_config.return_value = mock_config
    
    result = detect(dummy_context)
    assert result.action == Action.ALLOW
    assert result.layer == Layer.WHITELIST

@pytest.mark.asyncio
@patch("waf.detector.get_config")
async def test_blacklist_blocks(mock_get_config, dummy_context, mock_config):
    mock_config.blacklist_ips = ["192.168.1.1"]
    mock_get_config.return_value = mock_config
    
    result = detect(dummy_context)
    assert result.action == Action.BLOCK
    assert result.layer == Layer.BLACKLIST

@pytest.mark.asyncio
@patch("waf.detector.get_config")
async def test_static_file_skips_deep_inspection(mock_get_config, dummy_context, mock_config):
    mock_get_config.return_value = mock_config
    dummy_context.path = "/assets/style.css"
    
    result = detect(dummy_context)
    assert result.action == Action.ALLOW
    assert result.layer == Layer.NONE

@pytest.mark.asyncio
@patch("waf.signatures.scan")
@patch("waf.detector.get_config")
async def test_signature_hit_blocks(mock_get_config, mock_sig_scan, dummy_context, mock_config):
    mock_get_config.return_value = mock_config
    
    mock_hit = MagicMock()
    mock_hit.rule_id = "SQLI_001"
    mock_hit.attack_type = AttackType.SQLI
    mock_sig_scan.return_value = mock_hit
    
    result = detect(dummy_context)
    assert result.action == Action.BLOCK
    assert result.layer == Layer.SIGNATURE
    assert result.attack_type == AttackType.SQLI

@pytest.mark.asyncio
@patch("waf.detector._get_ai_score_lru")
@patch("waf.detector.get_config")
async def test_ai_high_confidence_blocks(mock_get_config, mock_ai_score, dummy_context, mock_config):
    mock_get_config.return_value = mock_config
    mock_ai_score.return_value = 0.95
    
    result = detect(dummy_context)
    assert result.action == Action.BLOCK
    assert result.layer == Layer.AI

@pytest.mark.asyncio
@patch("waf.detector._get_ai_score_lru")
@patch("waf.detector.get_config")
async def test_ai_low_confidence_allows(mock_get_config, mock_ai_score, dummy_context, mock_config):
    mock_get_config.return_value = mock_config
    mock_ai_score.return_value = 0.2
    
    result = detect(dummy_context)
    assert result.action == Action.ALLOW
    assert result.layer == Layer.AI

@pytest.mark.asyncio
@patch("waf.detector._get_ai_score_lru")
@patch("waf.detector.get_config")
async def test_ai_monitor_zone(mock_get_config, mock_ai_score, dummy_context, mock_config):
    mock_get_config.return_value = mock_config
    mock_ai_score.return_value = 0.7
    
    result = detect(dummy_context)
    assert result.action == Action.MONITOR
    assert result.layer == Layer.AI

@pytest.mark.asyncio
@patch("waf.detector._get_ai_score_lru")
@patch("waf.detector.get_config")
async def test_fail_open(mock_get_config, mock_ai_score, dummy_context, mock_config):
    """Verify that if an engine throws an unhandled exception, fail-open configuration allows traffic."""
    mock_get_config.return_value = mock_config
    # Force a crash in the final layer (AI) to trigger the ultimate fail-open fallthrough
    mock_ai_score.side_effect = Exception("Critical AI pipeline failure")
    
    result = detect(dummy_context)
    assert result.action == Action.ALLOW
    assert result.layer == Layer.NONE
    assert "fallthrough" in result.reason.lower()

@pytest.mark.asyncio
@patch("waf.detector._get_ai_score_lru")
@patch("waf.detector.get_config")
async def test_processing_time_recorded(mock_get_config, mock_ai_score, dummy_context, mock_config):
    mock_get_config.return_value = mock_config
    mock_ai_score.return_value = 0.1
    
    result = detect(dummy_context)
    
    assert result.processing_time_ms is not None
    assert result.processing_time_ms >= 0.0
    assert result.processing_time_ms < 15.0