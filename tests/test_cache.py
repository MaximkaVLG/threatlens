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
