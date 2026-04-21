"""Tests for SHA256 result cache."""

import tempfile
import pytest
from threatlens.cache import AnalysisCache


@pytest.fixture
def cache():
    return AnalysisCache(db_path=tempfile.mktemp(suffix=".db"))


class FakeResult:
    file = "test.exe"
    size = 1234
    file_type = "PE executable"
    sha256 = "aabbccdd11223344"
    md5 = "md5hash123"
    risk_score = 85
    risk_level = "HIGH"
    findings = ["[injection] CreateRemoteThread", "[network] HTTP request"]
    explanation = "This is a RAT."
    recommendations = ["Delete immediately"]
    heuristic_verdicts = []
    yara_matches = []


class TestCache:
    def test_put_and_get(self, cache):
        cache.put(FakeResult(), scan_time=0.5)
        result = cache.get("aabbccdd11223344")
        assert result is not None
        assert result["risk_level"] == "HIGH"
        assert result["risk_score"] == 85

    def test_get_missing(self, cache):
        result = cache.get("nonexistent_hash")
        assert result is None

    def test_scan_count(self, cache):
        cache.put(FakeResult())
        cache.get("aabbccdd11223344")
        cache.get("aabbccdd11223344")
        r = cache.get("aabbccdd11223344")
        assert r["scan_count"] >= 3

    def test_search_prefix(self, cache):
        cache.put(FakeResult())
        results = cache.search("aabbcc")
        assert len(results) == 1
        assert results[0]["sha256"] == "aabbccdd11223344"

    def test_search_no_match(self, cache):
        results = cache.search("zzz")
        assert len(results) == 0

    def test_stats(self, cache):
        cache.put(FakeResult())
        stats = cache.get_stats()
        assert stats["total_files"] == 1
        assert "by_risk_level" in stats

    def test_history(self, cache):
        cache.put(FakeResult())
        history = cache.get_history(limit=10)
        assert len(history) == 1
        assert history[0]["file_name"] == "test.exe"


class TestScanEvents:
    def test_record_scan_event_and_aggregate(self, cache):
        cache.record_scan_event("file", "malicious", 120, file_size_bytes=4096, client_ip_hash="h1")
        cache.record_scan_event("file", "clean", 80, file_size_bytes=100, client_ip_hash="h2")
        cache.record_scan_event("pcap", "DDoS", 2100, file_size_bytes=500_000, client_ip_hash="h1")
        cache.record_scan_event("hash_lookup", "found", 5, client_ip_hash="h2")

        stats = cache.get_usage_stats()
        assert stats["total_scans"] == 4
        assert stats["scans_by_type"] == {"file": 2, "pcap": 1, "hash_lookup": 1}
        assert stats["threats_detected_total"] == 2  # malicious + DDoS (not BENIGN)
        assert stats["unique_users_total"] == 2
        assert stats["unique_users_7d"] == 2
        assert stats["scans_last_24h"] == 4
        assert stats["scans_last_7d"] == 4
        assert stats["avg_scan_duration_ms"] > 0
        assert stats["first_scan_at"] is not None
        assert isinstance(stats["daily_scans_last_30d"], list)

    def test_empty_stats(self, cache):
        stats = cache.get_usage_stats()
        assert stats["total_scans"] == 0
        assert stats["unique_users_total"] == 0
        assert stats["threats_detected_total"] == 0
        assert stats["first_scan_at"] is None
        assert stats["avg_scan_duration_ms"] == 0.0
        assert stats["scans_by_type"] == {"file": 0, "pcap": 0, "hash_lookup": 0}

    def test_pcap_benign_not_threat(self, cache):
        cache.record_scan_event("pcap", "BENIGN", 1000, client_ip_hash="h1")
        stats = cache.get_usage_stats()
        assert stats["threats_detected_total"] == 0

    def test_empty_ip_hash_not_counted_as_unique(self, cache):
        cache.record_scan_event("file", "clean", 10, client_ip_hash="")
        cache.record_scan_event("file", "clean", 10, client_ip_hash="")
        stats = cache.get_usage_stats()
        assert stats["total_scans"] == 2
        assert stats["unique_users_total"] == 0


class TestHashClientIp:
    def test_same_ip_same_hash(self):
        from threatlens.cache import hash_client_ip
        assert hash_client_ip("1.2.3.4") == hash_client_ip("1.2.3.4")

    def test_different_ip_different_hash(self):
        from threatlens.cache import hash_client_ip
        assert hash_client_ip("1.2.3.4") != hash_client_ip("5.6.7.8")

    def test_empty_returns_empty(self):
        from threatlens.cache import hash_client_ip
        assert hash_client_ip("") == ""
        assert hash_client_ip(None) == ""

    def test_invalid_ip_still_hashes(self):
        from threatlens.cache import hash_client_ip
        h = hash_client_ip("not-an-ip")
        assert h and len(h) == 64
