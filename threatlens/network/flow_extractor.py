"""PCAP -> CIC-IDS2017 flow features.

Reads a PCAP file with scapy, aggregates packets into bidirectional flows
keyed by (src_ip, src_port, dst_ip, dst_port, protocol), then computes the
70 statistical features produced by CICFlowMeter (the tool used to generate
CIC-IDS2017). This lets flows extracted from live traffic be fed directly
into the models trained on CIC-IDS2017.

Feature naming follows the CIC-IDS2017 CSV columns exactly (including the
duplicate "Fwd Header Length.1" column).

Notes on CICFlowMeter conventions:
    - Flow Duration and all IAT values are in microseconds.
    - Forward direction = source of the first packet in the flow.
    - Active/Idle periods are split by a 5-second inactivity threshold.
    - TCP flag "CWE" in CIC-IDS2017 corresponds to CWR (bit 0x80) — the
      original dataset uses the older typo.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# Inactivity threshold separating active vs idle periods (CICFlowMeter default)
ACTIVE_IDLE_THRESHOLD_US = 5_000_000  # 5 seconds in microseconds

# TCP flag bitmasks
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_ECE = 0x40
TCP_CWR = 0x80  # labeled "CWE" in CIC-IDS2017

# Exact 70 columns kept after variance filtering (matches feature_pipeline.joblib)
CIC_FEATURE_COLUMNS: List[str] = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Fwd URG Flags",
    "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
    "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count",
    "Down/Up Ratio", "Average Packet Size",
    "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Fwd Header Length.1",
    "Subflow Fwd Packets", "Subflow Fwd Bytes",
    "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]


@dataclass
class PacketInfo:
    """Compact packet summary used for flow aggregation."""
    ts_us: int          # timestamp in microseconds since epoch
    total_length: int   # IP total length (headers + payload)
    header_length: int  # IP header + TCP/UDP header length
    payload_length: int
    flags: int          # TCP flags byte (0 for non-TCP)
    window: int         # TCP receive window (0 for non-TCP)


@dataclass
class Flow:
    """Bidirectional flow keyed by the first packet's 5-tuple."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    fwd: List[PacketInfo] = field(default_factory=list)
    bwd: List[PacketInfo] = field(default_factory=list)
    # CIC-IDS2017 encodes "no SYN seen" as 0 in Init_Win_bytes_* columns; match that.
    init_win_fwd: int = 0
    init_win_bwd: int = 0
    min_seg_size_fwd: int = -1  # sentinel; exposed as 0 in compute_features when unseen

    def add(self, pkt: PacketInfo, is_forward: bool) -> None:
        if is_forward:
            self.fwd.append(pkt)
            if pkt.flags & TCP_SYN and not self._seen_fwd_syn:
                self.init_win_fwd = pkt.window
                self._seen_fwd_syn = True
            if self.min_seg_size_fwd == -1 or pkt.header_length < self.min_seg_size_fwd:
                self.min_seg_size_fwd = pkt.header_length
        else:
            self.bwd.append(pkt)
            if pkt.flags & TCP_SYN and not self._seen_bwd_syn:
                self.init_win_bwd = pkt.window
                self._seen_bwd_syn = True

    def __post_init__(self):
        # Track whether we've recorded the initial SYN window per direction.
        # Using separate flags (rather than "== 0") avoids mistaking a legitimate
        # zero-window SYN for "no SYN seen yet".
        self._seen_fwd_syn = False
        self._seen_bwd_syn = False

    def all_packets_sorted(self) -> List[Tuple[int, PacketInfo, bool]]:
        """All packets across both directions, sorted by timestamp. Returns (ts_us, pkt, is_fwd)."""
        combined: List[Tuple[int, PacketInfo, bool]] = []
        combined.extend((p.ts_us, p, True) for p in self.fwd)
        combined.extend((p.ts_us, p, False) for p in self.bwd)
        combined.sort(key=lambda t: t[0])
        return combined


def _stats(values: List[float]) -> Tuple[float, float, float, float, float]:
    """Return (sum, mean, std, max, min). Empty input -> all zeros."""
    if not values:
        return 0.0, 0.0, 0.0, 0.0, 0.0
    arr = np.asarray(values, dtype=np.float64)
    return float(arr.sum()), float(arr.mean()), float(arr.std()), float(arr.max()), float(arr.min())


def _iats_microseconds(timestamps_us: List[int]) -> List[float]:
    """Inter-arrival times in microseconds between consecutive packets."""
    if len(timestamps_us) < 2:
        return []
    arr = np.asarray(timestamps_us, dtype=np.int64)
    return np.diff(arr).astype(np.float64).tolist()


def _active_idle_periods(
    timestamps_us: List[int],
    threshold_us: int = ACTIVE_IDLE_THRESHOLD_US,
) -> Tuple[List[float], List[float]]:
    """Split flow timeline into active and idle periods based on IAT threshold.

    Active period = continuous stretch of packets whose consecutive IATs are
    all <= threshold. Idle period = gap between two such stretches.
    """
    if len(timestamps_us) < 2:
        return [], []

    active: List[float] = []
    idle: List[float] = []
    segment_start = timestamps_us[0]
    last_ts = timestamps_us[0]

    for ts in timestamps_us[1:]:
        gap = ts - last_ts
        if gap > threshold_us:
            active.append(float(last_ts - segment_start))
            idle.append(float(gap))
            segment_start = ts
        last_ts = ts

    active.append(float(last_ts - segment_start))
    return active, idle


def compute_features(flow: Flow) -> Dict[str, float]:
    """Compute the 70 CIC-IDS2017 features for a single flow."""
    fwd_lengths = [p.total_length for p in flow.fwd]
    bwd_lengths = [p.total_length for p in flow.bwd]
    fwd_timestamps = sorted(p.ts_us for p in flow.fwd)
    bwd_timestamps = sorted(p.ts_us for p in flow.bwd)
    all_timestamps = sorted(p.ts_us for p in flow.fwd + flow.bwd)

    total_fwd = len(flow.fwd)
    total_bwd = len(flow.bwd)
    total_pkts = total_fwd + total_bwd
    total_fwd_bytes = sum(fwd_lengths)
    total_bwd_bytes = sum(bwd_lengths)
    total_bytes = total_fwd_bytes + total_bwd_bytes

    duration_us = (all_timestamps[-1] - all_timestamps[0]) if total_pkts > 1 else 0
    duration_sec = duration_us / 1_000_000.0 if duration_us > 0 else 0.0

    # Per-direction packet-length stats
    _, fwd_len_mean, fwd_len_std, fwd_len_max, fwd_len_min = _stats(fwd_lengths)
    _, bwd_len_mean, bwd_len_std, bwd_len_max, bwd_len_min = _stats(bwd_lengths)

    # IAT stats
    flow_iats = _iats_microseconds(all_timestamps)
    fwd_iats = _iats_microseconds(fwd_timestamps)
    bwd_iats = _iats_microseconds(bwd_timestamps)
    _, flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = _stats(flow_iats)
    fwd_iat_total, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = _stats(fwd_iats)
    bwd_iat_total, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = _stats(bwd_iats)

    # Flag counts (all directions)
    def count_flag(mask: int) -> int:
        return sum(1 for p in flow.fwd + flow.bwd if p.flags & mask)

    # Forward-only flag counts
    fwd_psh = sum(1 for p in flow.fwd if p.flags & TCP_PSH)
    fwd_urg = sum(1 for p in flow.fwd if p.flags & TCP_URG)

    # Header-length totals
    fwd_header_total = sum(p.header_length for p in flow.fwd)
    bwd_header_total = sum(p.header_length for p in flow.bwd)

    # Packet length stats across both directions
    all_lengths = fwd_lengths + bwd_lengths
    if all_lengths:
        pkt_len_min = float(min(all_lengths))
        pkt_len_max = float(max(all_lengths))
        pkt_len_arr = np.asarray(all_lengths, dtype=np.float64)
        pkt_len_mean = float(pkt_len_arr.mean())
        pkt_len_std = float(pkt_len_arr.std())
        pkt_len_var = float(pkt_len_arr.var())
    else:
        pkt_len_min = pkt_len_max = pkt_len_mean = pkt_len_std = pkt_len_var = 0.0

    # Active / Idle periods
    active_times, idle_times = _active_idle_periods(all_timestamps)
    _, active_mean, active_std, active_max, active_min = _stats(active_times)
    _, idle_mean, idle_std, idle_max, idle_min = _stats(idle_times)

    # Rates
    flow_bytes_per_sec = (total_bytes / duration_sec) if duration_sec > 0 else 0.0
    flow_pkts_per_sec = (total_pkts / duration_sec) if duration_sec > 0 else 0.0
    fwd_pkts_per_sec = (total_fwd / duration_sec) if duration_sec > 0 else 0.0
    bwd_pkts_per_sec = (total_bwd / duration_sec) if duration_sec > 0 else 0.0

    # Data packets (payload > 0) in forward direction
    act_data_fwd = sum(1 for p in flow.fwd if p.payload_length > 0)

    # Down/Up ratio = bwd packets / fwd packets (CICFlowMeter convention)
    down_up_ratio = (total_bwd / total_fwd) if total_fwd > 0 else 0.0

    # Average packet size = total bytes / total packets
    avg_pkt_size = (total_bytes / total_pkts) if total_pkts > 0 else 0.0

    # Segment size = payload / data packets (CICFlowMeter approximates with mean pkt length)
    avg_fwd_seg = fwd_len_mean
    avg_bwd_seg = bwd_len_mean

    return {
        "Destination Port": float(flow.dst_port),
        "Flow Duration": float(duration_us),
        "Total Fwd Packets": float(total_fwd),
        "Total Backward Packets": float(total_bwd),
        "Total Length of Fwd Packets": float(total_fwd_bytes),
        "Total Length of Bwd Packets": float(total_bwd_bytes),
        "Fwd Packet Length Max": float(fwd_len_max),
        "Fwd Packet Length Min": float(fwd_len_min),
        "Fwd Packet Length Mean": float(fwd_len_mean),
        "Fwd Packet Length Std": float(fwd_len_std),
        "Bwd Packet Length Max": float(bwd_len_max),
        "Bwd Packet Length Min": float(bwd_len_min),
        "Bwd Packet Length Mean": float(bwd_len_mean),
        "Bwd Packet Length Std": float(bwd_len_std),
        "Flow Bytes/s": float(flow_bytes_per_sec),
        "Flow Packets/s": float(flow_pkts_per_sec),
        "Flow IAT Mean": float(flow_iat_mean),
        "Flow IAT Std": float(flow_iat_std),
        "Flow IAT Max": float(flow_iat_max),
        "Flow IAT Min": float(flow_iat_min),
        "Fwd IAT Total": float(fwd_iat_total),
        "Fwd IAT Mean": float(fwd_iat_mean),
        "Fwd IAT Std": float(fwd_iat_std),
        "Fwd IAT Max": float(fwd_iat_max),
        "Fwd IAT Min": float(fwd_iat_min),
        "Bwd IAT Total": float(bwd_iat_total),
        "Bwd IAT Mean": float(bwd_iat_mean),
        "Bwd IAT Std": float(bwd_iat_std),
        "Bwd IAT Max": float(bwd_iat_max),
        "Bwd IAT Min": float(bwd_iat_min),
        "Fwd PSH Flags": float(fwd_psh),
        "Fwd URG Flags": float(fwd_urg),
        "Fwd Header Length": float(fwd_header_total),
        "Bwd Header Length": float(bwd_header_total),
        "Fwd Packets/s": float(fwd_pkts_per_sec),
        "Bwd Packets/s": float(bwd_pkts_per_sec),
        "Min Packet Length": pkt_len_min,
        "Max Packet Length": pkt_len_max,
        "Packet Length Mean": pkt_len_mean,
        "Packet Length Std": pkt_len_std,
        "Packet Length Variance": pkt_len_var,
        "FIN Flag Count": float(count_flag(TCP_FIN)),
        "SYN Flag Count": float(count_flag(TCP_SYN)),
        "RST Flag Count": float(count_flag(TCP_RST)),
        "PSH Flag Count": float(count_flag(TCP_PSH)),
        "ACK Flag Count": float(count_flag(TCP_ACK)),
        "URG Flag Count": float(count_flag(TCP_URG)),
        "CWE Flag Count": float(count_flag(TCP_CWR)),
        "ECE Flag Count": float(count_flag(TCP_ECE)),
        "Down/Up Ratio": float(down_up_ratio),
        "Average Packet Size": float(avg_pkt_size),
        "Avg Fwd Segment Size": float(avg_fwd_seg),
        "Avg Bwd Segment Size": float(avg_bwd_seg),
        "Fwd Header Length.1": float(fwd_header_total),
        "Subflow Fwd Packets": float(total_fwd),
        "Subflow Fwd Bytes": float(total_fwd_bytes),
        "Subflow Bwd Packets": float(total_bwd),
        "Subflow Bwd Bytes": float(total_bwd_bytes),
        "Init_Win_bytes_forward": float(flow.init_win_fwd),
        "Init_Win_bytes_backward": float(flow.init_win_bwd),
        "act_data_pkt_fwd": float(act_data_fwd),
        "min_seg_size_forward": float(flow.min_seg_size_fwd if flow.min_seg_size_fwd >= 0 else 0),
        "Active Mean": float(active_mean),
        "Active Std": float(active_std),
        "Active Max": float(active_max),
        "Active Min": float(active_min),
        "Idle Mean": float(idle_mean),
        "Idle Std": float(idle_std),
        "Idle Max": float(idle_max),
        "Idle Min": float(idle_min),
    }


class FlowExtractor:
    """Reads a PCAP and yields a DataFrame of flows with 70 CIC-IDS2017 features.

    Usage:
        extractor = FlowExtractor()
        df = extractor.extract("sample.pcap")
        # df has columns matching CIC_FEATURE_COLUMNS plus 5-tuple identifiers.
    """

    def __init__(self, flow_timeout_sec: float = 120.0):
        """Flow timeout: if a flow sees no packets for this long, it is finalized
        and a new flow starts on the next matching packet. CICFlowMeter default
        is 120 seconds.
        """
        self.flow_timeout_us = int(flow_timeout_sec * 1_000_000)

    def extract(self, pcap_path: str) -> pd.DataFrame:
        """Parse a PCAP file and return a DataFrame with one row per flow."""
        from scapy.all import PcapReader, TCP, UDP, IP, IPv6

        active_flows: Dict[Tuple, Flow] = {}
        finalized: List[Flow] = []
        packet_count = 0
        parse_errors = 0
        non_ip = 0

        logger.info("Reading PCAP: %s", pcap_path)

        with PcapReader(pcap_path) as reader:
            for pkt in reader:
                packet_count += 1
                try:
                    parsed = _parse_packet(pkt, TCP, UDP, IP, IPv6)
                except Exception:
                    parse_errors += 1
                    continue
                if parsed is None:
                    non_ip += 1
                    continue

                fwd_key, rev_key, pkt_info = parsed

                if fwd_key in active_flows:
                    flow = active_flows[fwd_key]
                    is_forward = True
                elif rev_key in active_flows:
                    flow = active_flows[rev_key]
                    is_forward = False
                else:
                    flow = _new_flow(fwd_key)
                    active_flows[fwd_key] = flow
                    is_forward = True

                # Timeout check relative to last seen packet in this flow.
                last_ts = max(
                    (p.ts_us for p in flow.fwd + flow.bwd),
                    default=pkt_info.ts_us,
                )
                if pkt_info.ts_us - last_ts > self.flow_timeout_us and (flow.fwd or flow.bwd):
                    finalized.append(flow)
                    flow = _new_flow(fwd_key)
                    # Replace by canonical key (the one currently stored)
                    stored_key = fwd_key if fwd_key in active_flows else rev_key
                    active_flows[stored_key] = flow
                    is_forward = True

                flow.add(pkt_info, is_forward=is_forward)

        finalized.extend(active_flows.values())
        logger.info(
            "Parsed %d packets (%d non-IP, %d parse errors) into %d flows",
            packet_count, non_ip, parse_errors, len(finalized),
        )

        if not finalized:
            return pd.DataFrame(columns=CIC_FEATURE_COLUMNS + _META_COLUMNS)

        rows = []
        for flow in finalized:
            features = compute_features(flow)
            features["src_ip"] = flow.src_ip
            features["dst_ip"] = flow.dst_ip
            features["src_port"] = flow.src_port
            features["protocol"] = flow.protocol
            rows.append(features)

        df = pd.DataFrame(rows)
        for col in CIC_FEATURE_COLUMNS:
            if col not in df.columns:
                df[col] = 0.0
        return df


_META_COLUMNS = ["src_ip", "dst_ip", "src_port", "protocol"]


def _new_flow(flow_key: Tuple) -> Flow:
    src_ip, src_port, dst_ip, dst_port, proto = flow_key
    return Flow(
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        protocol=proto,
    )


def _parse_packet(pkt, TCP, UDP, IP, IPv6):
    """Extract (fwd_key, rev_key, PacketInfo) from a scapy packet.

    Returns None for non-IP or unsupported packets.
    """
    if IP in pkt:
        ip_layer = pkt[IP]
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
        ip_hdr_len = ip_layer.ihl * 4 if ip_layer.ihl else 20
        total_length = int(getattr(ip_layer, "len", len(pkt)))
    elif IPv6 in pkt:
        ip_layer = pkt[IPv6]
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
        ip_hdr_len = 40
        total_length = int(getattr(ip_layer, "plen", 0)) + ip_hdr_len
    else:
        return None

    src_port = 0
    dst_port = 0
    flags = 0
    window = 0
    transport_hdr_len = 0
    payload_length = 0

    if TCP in pkt:
        tcp = pkt[TCP]
        proto = 6
        src_port, dst_port = int(tcp.sport), int(tcp.dport)
        flags = int(tcp.flags)
        window = int(tcp.window)
        transport_hdr_len = int(tcp.dataofs) * 4 if tcp.dataofs else 20
        payload_length = max(0, total_length - ip_hdr_len - transport_hdr_len)
    elif UDP in pkt:
        udp = pkt[UDP]
        proto = 17
        src_port, dst_port = int(udp.sport), int(udp.dport)
        transport_hdr_len = 8
        payload_length = max(0, total_length - ip_hdr_len - transport_hdr_len)
    else:
        proto_field = "proto" if IP in pkt else "nh"
        proto = int(getattr(ip_layer, proto_field, 0) or 0)
        payload_length = max(0, total_length - ip_hdr_len)

    ts_us = int(float(pkt.time) * 1_000_000)
    header_length = ip_hdr_len + transport_hdr_len

    pkt_info = PacketInfo(
        ts_us=ts_us,
        total_length=total_length,
        header_length=header_length,
        payload_length=payload_length,
        flags=flags,
        window=window,
    )
    fwd_key = (src_ip, src_port, dst_ip, dst_port, proto)
    rev_key = (dst_ip, dst_port, src_ip, src_port, proto)
    return fwd_key, rev_key, pkt_info


# ---------------------------------------------------------------------------
# cicflowmeter-backed extractor (default)
# ---------------------------------------------------------------------------
#
# The legacy FlowExtractor above mirrors CICFlowMeter's algorithm but is an
# independent re-implementation. Small differences from the original Java
# CICFlowMeter (which was used to produce CIC-IDS2017) cause feature drift
# that degrades prediction accuracy on real PCAPs.
#
# CicFlowExtractor delegates to the `cicflowmeter` Python port, which is a
# direct translation of the original tool and therefore produces features
# aligned with the training data.


def _safe_float(v, default: float = 0.0) -> float:
    """Coerce any scalar to float, mapping None / NaN / errors to `default`."""
    if v is None:
        return default
    try:
        f = float(v)
    except (TypeError, ValueError):
        return default
    if f != f:  # NaN
        return default
    return f


_SEC_TO_US = 1_000_000.0


def _us(d: dict, key: str) -> float:
    """Read a seconds-valued field from cicflowmeter and return microseconds.

    CIC-IDS2017 stores Flow Duration, all IAT fields, and Active/Idle periods
    in microseconds. cicflowmeter exposes the same quantities in seconds.
    """
    return _safe_float(d.get(key)) * _SEC_TO_US


def _map_cicflowmeter_row(d: dict) -> dict:
    """Translate a cicflowmeter get_data() dict into CIC-IDS2017 column names.

    Columns not produced by cicflowmeter (Subflow *, Avg * Segment Size,
    Fwd Header Length.1, CWE Flag Count) are derived from available fields.
    Time-valued fields are rescaled from seconds to microseconds.
    """
    fwd_pkts = _safe_float(d.get("tot_fwd_pkts"))
    bwd_pkts = _safe_float(d.get("tot_bwd_pkts"))
    fwd_bytes = _safe_float(d.get("totlen_fwd_pkts"))
    bwd_bytes = _safe_float(d.get("totlen_bwd_pkts"))
    fwd_hdr = _safe_float(d.get("fwd_header_len"))
    fwd_pkt_len_mean = _safe_float(d.get("fwd_pkt_len_mean"))
    bwd_pkt_len_mean = _safe_float(d.get("bwd_pkt_len_mean"))

    return {
        "Destination Port": _safe_float(d.get("dst_port")),
        "Flow Duration": _us(d, "flow_duration"),
        "Total Fwd Packets": fwd_pkts,
        "Total Backward Packets": bwd_pkts,
        "Total Length of Fwd Packets": fwd_bytes,
        "Total Length of Bwd Packets": bwd_bytes,
        "Fwd Packet Length Max": _safe_float(d.get("fwd_pkt_len_max")),
        "Fwd Packet Length Min": _safe_float(d.get("fwd_pkt_len_min")),
        "Fwd Packet Length Mean": fwd_pkt_len_mean,
        "Fwd Packet Length Std": _safe_float(d.get("fwd_pkt_len_std")),
        "Bwd Packet Length Max": _safe_float(d.get("bwd_pkt_len_max")),
        "Bwd Packet Length Min": _safe_float(d.get("bwd_pkt_len_min")),
        "Bwd Packet Length Mean": bwd_pkt_len_mean,
        "Bwd Packet Length Std": _safe_float(d.get("bwd_pkt_len_std")),
        "Flow Bytes/s": _safe_float(d.get("flow_byts_s")),
        "Flow Packets/s": _safe_float(d.get("flow_pkts_s")),
        "Flow IAT Mean": _us(d, "flow_iat_mean"),
        "Flow IAT Std": _us(d, "flow_iat_std"),
        "Flow IAT Max": _us(d, "flow_iat_max"),
        "Flow IAT Min": _us(d, "flow_iat_min"),
        "Fwd IAT Total": _us(d, "fwd_iat_tot"),
        "Fwd IAT Mean": _us(d, "fwd_iat_mean"),
        "Fwd IAT Std": _us(d, "fwd_iat_std"),
        "Fwd IAT Max": _us(d, "fwd_iat_max"),
        "Fwd IAT Min": _us(d, "fwd_iat_min"),
        "Bwd IAT Total": _us(d, "bwd_iat_tot"),
        "Bwd IAT Mean": _us(d, "bwd_iat_mean"),
        "Bwd IAT Std": _us(d, "bwd_iat_std"),
        "Bwd IAT Max": _us(d, "bwd_iat_max"),
        "Bwd IAT Min": _us(d, "bwd_iat_min"),
        "Fwd PSH Flags": _safe_float(d.get("fwd_psh_flags")),
        "Fwd URG Flags": _safe_float(d.get("fwd_urg_flags")),
        "Fwd Header Length": fwd_hdr,
        "Bwd Header Length": _safe_float(d.get("bwd_header_len")),
        "Fwd Packets/s": _safe_float(d.get("fwd_pkts_s")),
        "Bwd Packets/s": _safe_float(d.get("bwd_pkts_s")),
        "Min Packet Length": _safe_float(d.get("pkt_len_min")),
        "Max Packet Length": _safe_float(d.get("pkt_len_max")),
        "Packet Length Mean": _safe_float(d.get("pkt_len_mean")),
        "Packet Length Std": _safe_float(d.get("pkt_len_std")),
        "Packet Length Variance": _safe_float(d.get("pkt_len_var")),
        "FIN Flag Count": _safe_float(d.get("fin_flag_cnt")),
        "SYN Flag Count": _safe_float(d.get("syn_flag_cnt")),
        "RST Flag Count": _safe_float(d.get("rst_flag_cnt")),
        "PSH Flag Count": _safe_float(d.get("psh_flag_cnt")),
        "ACK Flag Count": _safe_float(d.get("ack_flag_cnt")),
        "URG Flag Count": _safe_float(d.get("urg_flag_cnt")),
        # cicflowmeter does not expose CWR count separately — CIC-IDS2017 has
        # it at 0 for virtually every flow, so defaulting to 0 is accurate.
        "CWE Flag Count": 0.0,
        "ECE Flag Count": _safe_float(d.get("ece_flag_cnt")),
        "Down/Up Ratio": _safe_float(d.get("down_up_ratio")),
        "Average Packet Size": _safe_float(d.get("pkt_size_avg")),
        # Avg Segment Size = mean packet length per direction (CICFlowMeter def).
        "Avg Fwd Segment Size": fwd_pkt_len_mean,
        "Avg Bwd Segment Size": bwd_pkt_len_mean,
        "Fwd Header Length.1": fwd_hdr,
        # Subflow fields with a single subflow equal the totals.
        "Subflow Fwd Packets": fwd_pkts,
        "Subflow Fwd Bytes": fwd_bytes,
        "Subflow Bwd Packets": bwd_pkts,
        "Subflow Bwd Bytes": bwd_bytes,
        "Init_Win_bytes_forward": _safe_float(d.get("init_fwd_win_byts")),
        "Init_Win_bytes_backward": _safe_float(d.get("init_bwd_win_byts")),
        "act_data_pkt_fwd": _safe_float(d.get("fwd_act_data_pkts")),
        "min_seg_size_forward": _safe_float(d.get("fwd_seg_size_min")),
        "Active Mean": _us(d, "active_mean"),
        "Active Std": _us(d, "active_std"),
        "Active Max": _us(d, "active_max"),
        "Active Min": _us(d, "active_min"),
        "Idle Mean": _us(d, "idle_mean"),
        "Idle Std": _us(d, "idle_std"),
        "Idle Max": _us(d, "idle_max"),
        "Idle Min": _us(d, "idle_min"),
        # 5-tuple metadata (not part of the 70 features; kept for display)
        "src_ip": d.get("src_ip", ""),
        "dst_ip": d.get("dst_ip", ""),
        "src_port": int(_safe_float(d.get("src_port"))),
        "protocol": int(_safe_float(d.get("protocol"))),
        # Epoch seconds of the first packet — used by the dashboard timeline.
        "timestamp": _safe_float(d.get("timestamp")),
    }


class _NullWriter:
    """No-op writer required by cicflowmeter's FlowSession constructor.

    We read flows directly from `session.flows` instead of relying on the
    writer, so this method never does anything meaningful.
    """
    def write(self, data: dict) -> None:
        pass


class CicFlowExtractor:
    """PCAP -> CIC-IDS2017 features via the `cicflowmeter` library.

    This is the default extractor because it matches the feature generator
    used to produce the CIC-IDS2017 CSVs our models were trained on.
    """

    def extract(self, pcap_path: str) -> pd.DataFrame:
        from cicflowmeter import flow_session as _fs_mod
        from cicflowmeter.flow_session import FlowSession
        from scapy.all import PcapReader

        # FlowSession's constructor insists on creating a writer. Patch the
        # factory (imported by-name into flow_session) so writer.write() is
        # a no-op — we only need the in-memory self.flows dict.
        orig_factory = _fs_mod.output_writer_factory
        _fs_mod.output_writer_factory = lambda *_a, **_k: _NullWriter()
        try:
            session = FlowSession(output_mode="none", output=None)
        finally:
            _fs_mod.output_writer_factory = orig_factory

        packet_count = 0
        errors = 0

        logger.info("Reading PCAP via cicflowmeter: %s", pcap_path)
        with PcapReader(pcap_path) as reader:
            for pkt in reader:
                packet_count += 1
                try:
                    session.process(pkt)
                except Exception:
                    errors += 1

        # Snapshot flows BEFORE garbage_collect (which empties the dict).
        # We need each Flow object itself (not just get_data()) to read the
        # raw epoch timestamp of its first packet for the dashboard timeline.
        flows = list(session.flows.values())
        logger.info(
            "Parsed %d packets (%d errors) into %d flows",
            packet_count, errors, len(flows),
        )

        rows = []
        for flow in flows:
            try:
                data = flow.get_data()
                epoch = float(flow.packets[0][0].time) if flow.packets else 0.0
                row = _map_cicflowmeter_row(data)
                row["timestamp"] = epoch
                rows.append(row)
            except Exception as e:
                logger.debug("Skipping flow with mapping error: %s", e)

        if not rows:
            return pd.DataFrame(
                columns=CIC_FEATURE_COLUMNS + ["src_ip", "dst_ip", "src_port", "protocol", "timestamp"]
            )
        return pd.DataFrame(rows)


# Public alias — new code should use `FlowExtractor`. The legacy
# implementation is kept under `LegacyFlowExtractor` for reference.
LegacyFlowExtractor = FlowExtractor
FlowExtractor = CicFlowExtractor
