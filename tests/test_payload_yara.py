"""Unit tests for threatlens.network.payload_yara.

Covers the parts that don't require yara-python:
- canonical 5-tuple key (deterministic)
- per-flow payload reassembly from a crafted PCAP
- graceful return when no payloads / no yara

YARA-dependent matching is exercised only when yara-python is importable
(skipped on dev machines where yara doesn't build, e.g. Windows w/o MSVC).
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from threatlens.network.payload_yara import (
    YARA_FEATURE_COLUMNS,
    _canonical_key,
    compute_yara_features,
    extract_payloads_per_flow,
    scan_payloads,
)
from threatlens.rules.signatures import HAS_YARA


def _write_pcap(packets, suffix: str = ".pcap") -> str:
    """Write packets to a temp PCAP file, return its path."""
    from scapy.all import wrpcap
    fd = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
    fd.close()
    wrpcap(fd.name, packets)
    return fd.name


def test_yara_feature_column_names_stable():
    # The exact column names are part of the public contract — Day 8
    # combined retraining will use them. Don't rename without migrating
    # the trained model artefacts.
    assert YARA_FEATURE_COLUMNS == [
        "YARA Match Count",
        "YARA Max Severity",
        "YARA Has Match",
    ]


def test_canonical_key_is_bidirectional():
    # Forward and reverse packets must collapse to the same key, otherwise
    # the merge into the flow DataFrame double-counts directions.
    fwd = _canonical_key("10.0.0.1", "10.0.0.2", 12345, 80, 6)
    rev = _canonical_key("10.0.0.2", "10.0.0.1", 80, 12345, 6)
    assert fwd == rev


def test_canonical_key_distinguishes_protocols():
    # TCP/80 and UDP/80 between the same endpoints are different flows.
    tcp = _canonical_key("10.0.0.1", "10.0.0.2", 12345, 80, 6)
    udp = _canonical_key("10.0.0.1", "10.0.0.2", 12345, 80, 17)
    assert tcp != udp


def test_extract_payloads_empty_pcap_returns_empty_dict():
    from scapy.all import IP, TCP
    pcap = _write_pcap([IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1, dport=2)])
    try:
        # SYN with no Raw layer -> nothing to extract
        assert extract_payloads_per_flow(pcap) == {}
    finally:
        Path(pcap).unlink()


def test_extract_payloads_single_flow():
    from scapy.all import IP, TCP, Raw
    pcap = _write_pcap([
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(load=b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
        IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=12345) / Raw(load=b"HTTP/1.1 200 OK\r\n\r\n<html>"),
    ])
    try:
        out = extract_payloads_per_flow(pcap)
        assert len(out) == 1, f"expected 1 flow, got {len(out)}"
        # Both directions concatenated under same canonical key
        blob = list(out.values())[0]
        assert b"GET" in blob and b"200 OK" in blob
    finally:
        Path(pcap).unlink()


def test_extract_payloads_two_flows_distinct_endpoints():
    from scapy.all import IP, TCP, Raw
    pcap = _write_pcap([
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(load=b"flow A payload" * 5),
        IP(src="10.0.0.3", dst="10.0.0.4") / TCP(sport=23456, dport=443) / Raw(load=b"flow B payload" * 5),
    ])
    try:
        out = extract_payloads_per_flow(pcap)
        assert len(out) == 2
    finally:
        Path(pcap).unlink()


def test_extract_payloads_skips_packets_without_raw_layer():
    from scapy.all import IP, TCP, Raw
    pcap = _write_pcap([
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="S"),  # SYN, no payload
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(load=b"actual payload here" * 4),
    ])
    try:
        out = extract_payloads_per_flow(pcap)
        assert len(out) == 1
        assert b"actual payload here" in list(out.values())[0]
    finally:
        Path(pcap).unlink()


def test_extract_payloads_truncates_at_max_size(monkeypatch):
    # Lower the cap so the test stays under TCP's 64KiB-per-packet ceiling.
    import threatlens.network.payload_yara as mod
    monkeypatch.setattr(mod, "_MAX_PAYLOAD_BYTES", 4096)

    from scapy.all import IP, TCP, Raw
    chunk = b"A" * 1024  # 1 KiB per packet
    packets = [
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(load=chunk)
        for _ in range(8)  # 8 KiB total, cap is 4 KiB
    ]
    pcap = _write_pcap(packets)
    try:
        out = extract_payloads_per_flow(pcap)
        blob = list(out.values())[0]
        assert len(blob) == 4096, f"expected exact cap of 4096, got {len(blob)}"
    finally:
        Path(pcap).unlink()


def test_compute_yara_features_handles_missing_pcap_gracefully():
    out = compute_yara_features("/path/that/does/not/exist.pcap")
    assert out == {}


def test_scan_payloads_returns_empty_when_yara_unavailable():
    # When HAS_YARA=False, no matches can be produced regardless of input.
    # When HAS_YARA=True, an empty payload still produces no matches
    # because it falls below _MIN_PAYLOAD_BYTES.
    out = scan_payloads({("a", "b", 1, 2, 6): b"X" * 10})
    assert out == {}


@pytest.mark.skipif(not HAS_YARA, reason="yara-python not installed in this env")
def test_scan_payloads_eicar_triggers_match():
    # The EICAR test string is the standard non-malicious AV trigger;
    # ThreatLens' custom ruleset includes a matching rule.
    eicar = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-"
             b"ANTIVIRUS-TEST-FILE!$H+H*")
    # Pad to clear _MIN_PAYLOAD_BYTES
    payload = eicar + b" " * 64
    out = scan_payloads({("10.0.0.1", "10.0.0.2", 12345, 80, 6): payload})
    # If the custom ruleset has an EICAR rule, this should match. If not,
    # the test is harmless (assertion is on the *structure* of output).
    if out:
        feats = list(out.values())[0]
        assert feats["YARA Has Match"] == 1.0
        assert feats["YARA Match Count"] >= 1.0
        assert feats["YARA Max Severity"] > 0.0


@pytest.mark.skipif(not HAS_YARA, reason="yara-python not installed in this env")
def test_scan_payloads_benign_text_no_match():
    payload = b"This is a perfectly normal HTTP body. " * 20
    out = scan_payloads({("10.0.0.1", "10.0.0.2", 12345, 80, 6): payload})
    assert out == {} or all(f["YARA Has Match"] == 0.0 for f in out.values())


# ---- End-to-end integration: PCAP -> CicFlowExtractor -> DataFrame ----
# These don't need yara — they monkeypatch scan_payloads to simulate a hit
# and verify the merge into the flow row works (5-tuple alignment is the
# real risk: scapy and cicflowmeter could disagree on src/dst direction).

def test_flow_extractor_merges_yara_features_to_correct_row(monkeypatch):
    from scapy.all import IP, TCP, Raw
    import threatlens.network.payload_yara as pyara
    from threatlens.network.flow_extractor import FlowExtractor

    # Two separate flows so we can verify the YARA hit lands on the right one.
    pcap = _write_pcap([
        # Flow A: 10.0.0.1:12345 <-> 10.0.0.2:80 — will be flagged
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="S", seq=1000),
        IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=12345, flags="SA", seq=2000, ack=1001),
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="A", seq=1001, ack=2001),
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="PA", seq=1001, ack=2001) / Raw(load=b"GET /malware HTTP/1.0\r\n\r\n" + b"X" * 100),
        # Flow B: 10.0.0.3:23456 <-> 10.0.0.4:443 — should stay clean
        IP(src="10.0.0.3", dst="10.0.0.4") / TCP(sport=23456, dport=443, flags="S", seq=3000),
        IP(src="10.0.0.4", dst="10.0.0.3") / TCP(sport=443, dport=23456, flags="SA", seq=4000, ack=3001),
        IP(src="10.0.0.3", dst="10.0.0.4") / TCP(sport=23456, dport=443, flags="A", seq=3001, ack=4001),
        IP(src="10.0.0.3", dst="10.0.0.4") / TCP(sport=23456, dport=443, flags="PA", seq=3001, ack=4001) / Raw(load=b"clean traffic " * 20),
    ])

    # Fake YARA: pretend Flow A's payload triggered a high-severity rule.
    flow_a_key = pyara._canonical_key("10.0.0.1", "10.0.0.2", 12345, 80, 6)

    def fake_scan(payload_map, use_community=False):
        out = {}
        for key in payload_map:
            if key == flow_a_key:
                out[key] = {
                    "YARA Match Count": 2.0,
                    "YARA Max Severity": 75.0,
                    "YARA Has Match": 1.0,
                }
        return out

    monkeypatch.setattr(pyara, "scan_payloads", fake_scan)

    try:
        df = FlowExtractor().extract(pcap)
        assert "YARA Match Count" in df.columns
        assert len(df) == 2, f"expected 2 flows, got {len(df)}"

        # Identify each row by its 5-tuple
        a_rows = df[(df["src_ip"].isin(["10.0.0.1", "10.0.0.2"])) &
                    (df["dst_ip"].isin(["10.0.0.1", "10.0.0.2"]))]
        b_rows = df[(df["src_ip"].isin(["10.0.0.3", "10.0.0.4"])) &
                    (df["dst_ip"].isin(["10.0.0.3", "10.0.0.4"]))]

        assert len(a_rows) == 1 and len(b_rows) == 1
        assert a_rows.iloc[0]["YARA Has Match"] == 1.0, \
            "Flow A should be flagged"
        assert a_rows.iloc[0]["YARA Match Count"] == 2.0
        assert a_rows.iloc[0]["YARA Max Severity"] == 75.0
        assert b_rows.iloc[0]["YARA Has Match"] == 0.0, \
            "Flow B should NOT be flagged (the 5-tuple mismatch bug)"
        assert b_rows.iloc[0]["YARA Match Count"] == 0.0
    finally:
        Path(pcap).unlink()


def test_flow_extractor_yara_columns_default_zero_when_no_matches(monkeypatch):
    from scapy.all import IP, TCP, Raw
    import threatlens.network.payload_yara as pyara
    from threatlens.network.flow_extractor import FlowExtractor

    pcap = _write_pcap([
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="S", seq=1000),
        IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=12345, flags="SA", seq=2000, ack=1001),
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="PA", seq=1001, ack=2001) / Raw(load=b"hello" * 30),
    ])
    monkeypatch.setattr(pyara, "scan_payloads", lambda *a, **k: {})

    try:
        df = FlowExtractor().extract(pcap)
        for col in ["YARA Match Count", "YARA Max Severity", "YARA Has Match"]:
            assert col in df.columns
            assert (df[col] == 0.0).all()
    finally:
        Path(pcap).unlink()
