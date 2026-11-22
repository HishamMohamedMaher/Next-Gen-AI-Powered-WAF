import datetime
from types import SimpleNamespace
from unittest.mock import Mock

import geoip2.errors
import httpx
import pytest

from waf import db, geoip, threat_intel
from waf.models import WAFEvent


@pytest.fixture
def cache(tmp_path):
    db.init_db(str(tmp_path / "reputation.db"))
    try:
        yield
    finally:
        db.close_db()


@pytest.mark.parametrize("ip", ["invalid", "127.0.0.1", "192.0.2.1", "240.0.0.1",
                                "100.64.0.1", "224.0.0.1", "ff02::1", "fec0::1", "fe80::1%eth0"])
def test_lookup_skips_nonpublic_addresses(ip, monkeypatch):
    get = Mock(side_effect=AssertionError("Unexpected network call"))
    monkeypatch.setattr(threat_intel.httpx, "get", get)
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
    assert threat_intel.lookup(ip) is None
    get.assert_not_called()


def test_lookup_reuses_cache_and_refreshes_expired_row(cache, monkeypatch):
    ip = "2606:4700:4700::1111"
    result = {"ipAddress": "2606:4700:4700:0:0:0:0:1111", "abuseConfidenceScore": 42}
    response = httpx.Response(
        200, json={"data": result}, request=httpx.Request("GET", threat_intel.ABUSEIPDB_URL)
    )
    get = Mock(return_value=response)
    monkeypatch.setattr(threat_intel.httpx, "get", get)
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
    assert threat_intel.lookup(ip) == result
    assert threat_intel.lookup(result["ipAddress"]) == result
    get.assert_called_once()
    assert get.call_args.kwargs["params"]["ipAddress"] == ip
    assert get.call_args.kwargs["headers"]["Key"] == "test-key"
    assert get.call_args.kwargs["timeout"] == 2.0
    assert get.call_args.kwargs["follow_redirects"] is False

    old = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=25)
    db._write_conn.execute("UPDATE abuseipdb_cache SET cached_at = ?", (old.isoformat(),))
    db._write_conn.commit()
    assert threat_intel._cache_get(ip) is None
    assert threat_intel.lookup(ip) == result
    assert get.call_count == 2


@pytest.mark.parametrize("score", [True, -1, 101, "92", None])
def test_invalid_api_response_is_not_cached(score, cache, monkeypatch):
    ip = "1.1.1.1"
    response = httpx.Response(
        200, json={"data": {"ipAddress": ip, "abuseConfidenceScore": score}},
        request=httpx.Request("GET", threat_intel.ABUSEIPDB_URL),
    )
    monkeypatch.setattr(threat_intel.httpx, "get", Mock(return_value=response))
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
    assert threat_intel.lookup(ip) is None
    assert db.get_abuseipdb_cache(ip) is None


def test_lookup_missing_key_timeout_and_corrupt_cache(cache, monkeypatch):
    ip = "8.8.8.8"
    db.cache_abuseipdb(ip, 1, "bad json")
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    get = Mock(side_effect=httpx.ReadTimeout("test timeout"))
    monkeypatch.setattr(threat_intel.httpx, "get", get)
    assert threat_intel.lookup(ip) is None
    get.assert_not_called()
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
    assert threat_intel.lookup(ip) is None
    get.assert_called_once()


def test_geoip_enrich_reopen_and_close(tmp_path, monkeypatch):
    first_path = tmp_path / "city.mmdb"
    first_path.touch()
    second_path = tmp_path / "replacement.mmdb"
    second_path.touch()
    invalid_path = tmp_path / "wrong.mmdb"
    invalid_path.touch()
    first = Mock()
    second = Mock()
    invalid = Mock()
    first.metadata.return_value.database_type = "GeoLite2-City"
    second.metadata.return_value.database_type = "GeoIP2-City"
    invalid.metadata.return_value.database_type = "GeoIP2-Country"
    first.city.return_value = SimpleNamespace(
        country=SimpleNamespace(iso_code="EG", name="Egypt"),
        location=SimpleNamespace(latitude=0, longitude=31.2),
    )
    second.city.side_effect = geoip2.errors.AddressNotFoundError("missing")
    reader = Mock(side_effect=[first, invalid, second])
    monkeypatch.setattr(geoip.geoip2.database, "Reader", reader)
    try:
        geoip.init(str(tmp_path / "missing.mmdb"))
        reader.assert_not_called()
        geoip.init(str(first_path))
        geoip.init(str(invalid_path))
        invalid.close.assert_called_once()
        geoip.enrich(WAFEvent(client_ip="10.0.0.1"))
        geoip.enrich(WAFEvent(client_ip="224.0.0.1"))
        first.city.assert_not_called()
        event = WAFEvent(client_ip="8.8.8.8")
        assert geoip.enrich(event) is event
        assert (event.country, event.latitude, event.longitude) == ("EG", 0.0, 31.2)

        geoip.init(str(second_path))
        first.close.assert_called_once()
        event = WAFEvent(client_ip="8.8.4.4")
        assert geoip.enrich(event).country is None
    finally:
        geoip.close()
    geoip.close()
    second.close.assert_called_once()


def test_geoip_handles_invalid_database_file(tmp_path):
    path = tmp_path / "invalid.mmdb"
    path.write_bytes(b"not a MaxMind database")
    geoip.close()
    geoip.init(str(path))
    assert geoip.enrich(WAFEvent(client_ip="1.1.1.1")).country is None
