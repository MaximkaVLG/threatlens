"""Tests for core analysis pipeline."""

import os
import pytest
from threatlens.core import analyze_file


class TestCoreAnalysis:
    def test_stealer_critical(self, stealer_script):
        r = analyze_file(stealer_script, use_cache=False)
        assert r.risk_level in ("HIGH", "CRITICAL")
        assert r.risk_score >= 50
        assert len(r.findings) > 0

    def test_clean_low(self, clean_script):
        r = analyze_file(clean_script, use_cache=False)
        assert r.risk_level == "LOW"
        assert r.risk_score < 15

    def test_pe_file(self, fake_pe):
        r = analyze_file(fake_pe, use_cache=False)
        assert r.sha256
        assert len(r.sha256) == 64

    def test_has_explanation(self, stealer_script):
        r = analyze_file(stealer_script, use_cache=False)
        assert r.explanation
        assert len(r.explanation) > 10

    def test_has_recommendations(self, stealer_script):
        r = analyze_file(stealer_script, use_cache=False)
        assert len(r.recommendations) > 0


class TestEdgeCases:
    def test_empty_file(self, tmp_file):
        p = tmp_file(b"", suffix=".exe")
        r = analyze_file(p, use_cache=False)
        assert "Empty" in str(r.findings)

    def test_directory_error(self):
        import tempfile
        d = tempfile.gettempdir()
        with pytest.raises(IsADirectoryError):
            analyze_file(d, use_cache=False)

    def test_nonexistent_error(self):
        with pytest.raises(FileNotFoundError):
            analyze_file("/nonexistent/file.exe", use_cache=False)

    def test_one_byte(self, tmp_file):
        p = tmp_file(b"X", suffix=".bin")
        r = analyze_file(p, use_cache=False)
        assert r.risk_score >= 0  # Should not crash

    def test_random_binary(self, tmp_file):
        import random
        p = tmp_file(bytes(random.randint(0, 255) for _ in range(1000)), suffix=".dll")
        r = analyze_file(p, use_cache=False)
        assert r.risk_score >= 0
