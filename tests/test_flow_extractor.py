"""Unit tests for threatlens.network.flow_extractor."""

import os
import time

import pytest
import pandas as pd

from threatlens.network import CicFlowExtractor, CIC_FEATURE_COLUMNS
from threatlens.network.flow_extractor import (
    LegacyFlowExtractor,
    _map_cicflowmeter_row,
    _safe_float,
)


# ---------------------------------------------------------------------------
# Pure-Python helpers (no scapy / no PCAP needed)
# ---------------------------------------------------------------------------


def test_safe_float_handles_none_nan_and_bad_values():
    assert _safe_float(None) == 0.0
    assert _safe_float("not a number") == 0.0
    assert _safe_float(float("nan")) == 0.0
    assert _safe_float("12.5") == 12.5
    assert _safe_float(-3) == -3.0
    assert _safe_float(None, default=42.0) == 42.0


def test_map_cicflowmeter_row_produces_full_schema():
    """Mapper must output every CIC-IDS2017 feature column plus metadata."""
    fake = {
        "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
        "src_port": 50000, "dst_port": 80, "protocol": 6,
        "flow_duration": 0.002,  # seconds -> should become 2000.0 microseconds
        "tot_fwd_pkts": 3, "tot_bwd_pkts": 2,
        "totlen_fwd_pkts": 180, "totlen_bwd_pkts": 240,
        "fwd_pkt_len_mean": 60.0, "bwd_pkt_len_mean": 120.0,
        "syn_flag_cnt": 1, "ack_flag_cnt": 2,
        "init_fwd_win_byts": 29200, "init_bwd_win_byts": 28960,
        "fwd_seg_size_min": 32, "fwd_act_data_pkts": 1,
        "fwd_header_len": 60, "bwd_header_len": 40,
    }
    row = _map_cicflowmeter_row(fake)
    missing = [c for c in CIC_FEATURE_COLUMNS if c not in row]
    assert not missing, f"Mapper dropped columns: {missing[:5]}"


def test_map_cicflowmeter_row_rescales_seconds_to_microseconds():
    """Time-valued fields must be multiplied by 1e6 (CIC-IDS2017 uses us)."""
    row = _map_cicflowmeter_row({"flow_duration": 0.003, "flow_iat_mean": 0.001})
    assert row["Flow Duration"] == pytest.approx(3000.0)
    assert row["Flow IAT Mean"] == pytest.approx(1000.0)


def test_map_cicflowmeter_row_fills_derived_subflow_fields():
    """Subflow fields are not produced by cicflowmeter; we derive them from totals."""
    row = _map_cicflowmeter_row({
        "tot_fwd_pkts": 10, "tot_bwd_pkts": 7,
        "totlen_fwd_pkts": 1500, "totlen_bwd_pkts": 900,
    })
    assert row["Subflow Fwd Packets"] == 10.0
    assert row["Subflow Fwd Bytes"] == 1500.0
    assert row["Subflow Bwd Packets"] == 7.0
    assert row["Subflow Bwd Bytes"] == 900.0
    # Avg segment size defaults to mean packet length (CICFlowMeter convention)
    assert row["Avg Fwd Segment Size"] == row["Fwd Packet Length Mean"]


def test_map_cicflowmeter_row_cwe_always_zero():
    """cicflowmeter doesn't expose CWR; we document that as 0.0 (matches CIC-IDS2017)."""
    assert _map_cicflowmeter_row({})["CWE Flag Count"] == 0.0


# ---------------------------------------------------------------------------
# Integration tests — round-trip a generated PCAP through the extractor
# ---------------------------------------------------------------------------


@pytest.fixture
def synthetic_pcap():
    """Generate a tiny PCAP with one bidirectional TCP flow + one UDP flow."""
    import tempfile
    scapy = pytest.importorskip("scapy.all")
    base = time.time()

    pkts = [
        # TCP handshake + data
        scapy.Ether()/scapy.IP(src="10.0.0.1", dst="10.0.0.2")
            /scapy.TCP(sport=50001, dport=80, flags="S", window=29200),
        scapy.Ether()/scapy.IP(src="10.0.0.2", dst="10.0.0.1")
            /scapy.TCP(sport=80, dport=50001, flags="SA", window=28960),
        scapy.Ether()/scapy.IP(src="10.0.0.1", dst="10.0.0.2")
            /scapy.TCP(sport=50001, dport=80, flags="A")/scapy.Raw(b"GET / HTTP/1.1\r\n\r\n"),
        scapy.Ether()/scapy.IP(src="10.0.0.2", dst="10.0.0.1")
            /scapy.TCP(sport=80, dport=50001, flags="PA")/scapy.Raw(b"HTTP/1.1 200 OK\r\n"),
        # UDP one-shot
        scapy.Ether()/scapy.IP(src="10.0.0.1", dst="8.8.8.8")
            /scapy.UDP(sport=53000, dport=53)/scapy.Raw(b"\x00" * 20),
    ]
    for i, p in enumerate(pkts):
        p.time = base + i * 0.001

    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    scapy.wrpcap(path, pkts)
    yield path
    try:
        os.unlink(path)
    except OSError:
        pass


def test_cic_flow_extractor_produces_required_columns(synthetic_pcap):
    df = CicFlowExtractor().extract(synthetic_pcap)
    assert not df.empty, "extractor produced zero flows on a 5-packet PCAP"
    for col in CIC_FEATURE_COLUMNS:
        assert col in df.columns, f"missing CIC-IDS2017 column {col!r}"
    for meta in ("src_ip", "dst_ip", "src_port", "protocol", "timestamp"):
        assert meta in df.columns


def test_cic_flow_extractor_separates_tcp_and_udp_flows(synthetic_pcap):
    df = CicFlowExtractor().extract(synthetic_pcap)
    assert set(df["protocol"]) == {6, 17}, f"expected TCP+UDP, got {set(df['protocol'])}"


def test_cic_flow_extractor_flow_duration_in_microseconds(synthetic_pcap):
    df = CicFlowExtractor().extract(synthetic_pcap)
    # Packet spacing was 1 ms = 1000 us. Durations must be in us, not seconds.
    tcp_row = df[df["protocol"] == 6].iloc[0]
    assert tcp_row["Flow Duration"] >= 1000.0, \
        f"flow duration {tcp_row['Flow Duration']} looks like seconds not microseconds"


def test_empty_pcap_produces_empty_dataframe():
    import tempfile
    scapy = pytest.importorskip("scapy.all")
    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    try:
        scapy.wrpcap(path, [])
        df = CicFlowExtractor().extract(path)
        assert df.empty
        # Columns still match schema so downstream code can concat safely
        for col in CIC_FEATURE_COLUMNS:
            assert col in df.columns
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_legacy_and_cic_extractors_are_both_exported():
    """Two alternative implementations must both remain reachable."""
    assert CicFlowExtractor is not LegacyFlowExtractor
