"""Unit tests for scripts/ingest_sandbox_pcaps.py (network-independent logic).

No real HTTP calls here — the scraping/download paths are exercised in
manual integration runs. Here we pin down the pure-Python pieces that
decide how free-form family names get mapped to the 7-class model
labels, how filename stems are built, and that we reject non-PCAP bytes
before they pollute the training parquet.
"""
from __future__ import annotations

import importlib.util
import io
import json
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "ingest_sandbox_pcaps.py"


def _load_module():
    """Load the script as a module without executing main()."""
    spec = importlib.util.spec_from_file_location("ingest_sandbox_pcaps",
                                                     SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ingest_sandbox_pcaps"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def mod():
    return _load_module()


# ---------------------------------------------------------------------------
# map_family_to_label
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("Lumma Stealer infection with follow-up malware", "Bot"),
    ("NetSupport RAT via ClickFix", "Bot"),
    ("Cobalt Strike beacon over HTTPS", "Bot"),
    ("Emotet epoch 5", "Bot"),
    ("RedLine Stealer C2 traffic", "Bot"),
    ("StealC from files impersonating cracked software", "Bot"),
    ("Mirai activity (Linux traffic)", "Bot"),
    ("CTU-Malware-Capture-Botnet-348-1 (Neris)", "Bot"),
    ("port scanning across subnet", "PortScan"),
    ("nmap sweep", "PortScan"),
    ("SSH brute-force from 185.x.x.x", "SSH-Patator"),
    ("FTP brute force attack", "FTP-Patator"),
    ("slowloris DoS against apache", "DoS slowloris"),
    ("HULK HTTP flood", "DoS Hulk"),
])
def test_map_family_to_label_known(mod, text, expected):
    assert mod.map_family_to_label(text) == expected


def test_map_family_to_label_unknown_returns_default(mod):
    assert mod.map_family_to_label("completely novel family xyz-2099") is None
    assert mod.map_family_to_label("", default="Bot") == "Bot"
    assert mod.map_family_to_label(None, default="Bot") == "Bot"  # type: ignore


def test_map_family_to_label_case_insensitive(mod):
    assert mod.map_family_to_label("LUMMA STEALER") == "Bot"
    assert mod.map_family_to_label("cobalt STRIKE") == "Bot"


# ---------------------------------------------------------------------------
# guess_family
# ---------------------------------------------------------------------------

def test_guess_family_prefers_known_keyword(mod):
    # "lumma" comes before "stealer" in the text but the mapping is by
    # keyword match, not first word — so a known family is preferred.
    assert mod.guess_family("2025-12-30 Lumma Stealer infection") == "lumma"
    assert mod.guess_family("Cobalt Strike beacon over 443") == "cobalt-strike"


def test_guess_family_multiword_slug(mod):
    result = mod.guess_family("NetSupport RAT via ClickFix activity")
    # NetSupport comes first so it wins; slug form: "netsupport"
    assert result in {"netsupport", "clickfix"}


def test_guess_family_empty_returns_unknown(mod):
    assert mod.guess_family("") == "unknown"
    assert mod.guess_family(None) == "unknown"  # type: ignore


# ---------------------------------------------------------------------------
# SampleMeta.stem
# ---------------------------------------------------------------------------

def test_sample_stem_is_filesystem_safe(mod):
    s = mod.SampleMeta(
        source="mta",
        sample_id="2025-12-30/file with spaces!",
        pcap_url="https://example.com/x.pcap",
        family="Cobalt Strike",
        label="Bot",
    )
    stem = s.stem
    assert "/" not in stem
    assert " " not in stem
    assert "!" not in stem
    # Label separator should use underscore not space
    assert "Bot" in stem
    # family must be slugified (spaces -> hyphens)
    assert "cobalt-strike" in stem.lower()


def test_sample_stem_deterministic(mod):
    s1 = mod.SampleMeta(source="s", sample_id="abc", pcap_url="u",
                         family="lumma", label="Bot")
    s2 = mod.SampleMeta(source="s", sample_id="abc", pcap_url="u",
                         family="lumma", label="Bot")
    assert s1.stem == s2.stem


# ---------------------------------------------------------------------------
# PCAP magic validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("magic", [
    b"\xd4\xc3\xb2\xa1",  # libpcap LE
    b"\xa1\xb2\xc3\xd4",  # libpcap BE
    b"\x4d\x3c\xb2\xa1",  # ns LE
    b"\xa1\xb2\x3c\x4d",  # ns BE
    b"\x0a\x0d\x0d\x0a",  # pcapng
])
def test_is_valid_pcap_bytes_accepts_known_magics(mod, magic):
    assert mod.is_valid_pcap_bytes(magic + b"\x00" * 100)


@pytest.mark.parametrize("head", [
    b"PK\x03\x04",   # zip
    b"\x1f\x8b\x08", # gzip (3 bytes only; not enough anyway)
    b"\x00\x00\x00\x00",
    b"NOT",
    b"",
])
def test_is_valid_pcap_bytes_rejects_non_pcap(mod, head):
    assert not mod.is_valid_pcap_bytes(head)


def test_is_valid_pcap_file_handles_missing_and_good(mod, tmp_path):
    missing = tmp_path / "nope.pcap"
    assert not mod.is_valid_pcap_file(missing)

    good = tmp_path / "good.pcap"
    good.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 200)
    assert mod.is_valid_pcap_file(good)

    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"not a pcap at all")
    assert not mod.is_valid_pcap_file(bad)


# ---------------------------------------------------------------------------
# extract_pcap_from_archive
# ---------------------------------------------------------------------------

def _make_zip(*, password: bytes = None, inner_name: str = "trace.pcap",
               inner_bytes: bytes = b"\xd4\xc3\xb2\xa1" + b"\x00" * 64) -> bytes:
    """Build a simple ZIP in memory containing one file."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if password:
            zf.setpassword(password)
        zf.writestr(inner_name, inner_bytes)
    return buf.getvalue()


def test_extract_pcap_from_archive_plain(mod):
    data = _make_zip(inner_bytes=b"\xd4\xc3\xb2\xa1" + b"A" * 32)
    pcap = mod.extract_pcap_from_archive(data, password=None,
                                            filename_hint="t.zip")
    assert pcap is not None
    assert pcap.startswith(b"\xd4\xc3\xb2\xa1")


def test_extract_pcap_from_archive_rejects_non_pcap_member(mod):
    # ZIP contains a file named .pcap but its bytes are garbage
    data = _make_zip(inner_bytes=b"definitely not a pcap")
    pcap = mod.extract_pcap_from_archive(data, password=None,
                                            filename_hint="t.zip")
    assert pcap is None


def test_extract_pcap_from_archive_no_pcap_member(mod):
    # ZIP with only a .txt
    data = _make_zip(inner_name="readme.txt", inner_bytes=b"hello")
    pcap = mod.extract_pcap_from_archive(data, password=None,
                                            filename_hint="t.zip")
    assert pcap is None


def test_extract_pcap_from_archive_bad_zip(mod):
    pcap = mod.extract_pcap_from_archive(b"garbage bytes",
                                            password=None, filename_hint="x")
    assert pcap is None


# ---------------------------------------------------------------------------
# Rate limiter (fake clock)
# ---------------------------------------------------------------------------

def test_rate_limited_client_enforces_min_interval(mod, monkeypatch):
    """The wrapper should sleep enough to honour min_interval_s.

    We replace time.sleep with a recorder and time.monotonic with a fake
    clock so the test doesn't actually block.
    """
    import time as real_time
    sleeps = []
    fake_now = [0.0]

    def fake_monotonic():
        return fake_now[0]

    def fake_sleep(dt):
        sleeps.append(dt)
        fake_now[0] += dt

    monkeypatch.setattr(mod.time, "monotonic", fake_monotonic)
    monkeypatch.setattr(mod.time, "sleep", fake_sleep)

    class DummyInner:
        def __init__(self):
            self.calls = 0

        def get(self, url, **kw):
            self.calls += 1
            fake_now[0] += 0.01  # pretend the request took 10ms
            return "resp"

        def close(self):
            pass

    inner = DummyInner()
    rlc = mod.RateLimitedClient(inner, min_interval_s=1.5)

    rlc.get("http://x")                # first call: no sleep expected
    rlc.get("http://y")                # second call: should sleep ~1.5-0.01
    rlc.get("http://z")                # third call: again ~1.5

    assert inner.calls == 3
    # Only the second and third calls trigger sleep
    assert len(sleeps) == 2
    for s in sleeps:
        assert 1.4 <= s <= 1.5 + 1e-6


# ---------------------------------------------------------------------------
# CLI parser smoke
# ---------------------------------------------------------------------------

def test_build_parser_defaults(mod):
    p = mod.build_parser()
    ns = p.parse_args([])
    assert ns.source == "all"
    assert ns.limit == 5
    assert ns.year == 2025
    assert ns.since_year == 2024
    assert ns.dry_run is False
    assert ns.mta_password == "infected"


def test_build_parser_dry_run_and_verbose(mod):
    ns = mod.build_parser().parse_args([
        "--source", "stratosphere", "--limit", "2",
        "--dry-run", "-vv",
    ])
    assert ns.source == "stratosphere"
    assert ns.limit == 2
    assert ns.dry_run is True
    assert ns.verbose == 2
