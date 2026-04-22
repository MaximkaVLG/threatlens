"""Per-flow YARA scanning of TCP/UDP payloads — file<->network synergy.

The CIC-IDS2017 statistics describe *how* a flow looks (byte counts,
timing, flag distributions). They cannot see *what* the flow carries.
This module reassembles the raw L7 payload of every flow in a PCAP and
runs the existing ThreatLens YARA ruleset against it, surfacing three
extra features per flow:

- ``YARA Match Count``   — number of distinct rules that fired
- ``YARA Max Severity``  — 0/25/50/75/100 (none/low/medium/high/critical)
- ``YARA Has Match``     — binary 0/1 indicator (cheap split feature)

These features are dormant (=0) for the majority of network traffic
(SYN floods, scans, encrypted SSH/TLS handshakes carry no scannable
payload) but light up sharply when a flow transports an actual
malicious file (HTTP download, SMTP attachment, FTP transfer). That
asymmetry is exactly what a tree-based classifier loves: low base rate,
high signal when present.

Robust to: PCAPs with zero TCP/UDP traffic, flows under ``min_size``,
yara-python missing, malformed packets.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)

# Canonical bidirectional 5-tuple: lower (ip,port) endpoint first so that
# forward and reverse packets land on the same key.
FlowKey = Tuple[str, str, int, int, int]

YARA_FEATURE_COLUMNS: List[str] = [
    "YARA Match Count",
    "YARA Max Severity",
    "YARA Has Match",
]

_SEVERITY_SCORES = {
    "low": 25.0,
    "medium": 50.0,
    "high": 75.0,
    "critical": 100.0,
}

# Skip flows with payloads smaller than this — too short for credible
# signature matches and dominated by protocol noise (TCP keepalives, etc.)
_MIN_PAYLOAD_BYTES = 64

# Cap concatenated payload at this size per flow. Long-lived HTTP downloads
# can easily push 100s of MB; YARA on multi-MB blobs is wasteful and rules
# are designed for headers/early bytes anyway.
_MAX_PAYLOAD_BYTES = 1 * 1024 * 1024  # 1 MiB

# Per-flow YARA timeout; default is 30 s in scan() but we have many flows.
_YARA_TIMEOUT_S = 5


def _canonical_key(src_ip: str, dst_ip: str,
                   src_port: int, dst_port: int,
                   proto: int) -> FlowKey:
    """Order endpoints so forward and reverse packets share a key."""
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    if a <= b:
        return (src_ip, dst_ip, src_port, dst_port, proto)
    return (dst_ip, src_ip, dst_port, src_port, proto)


def extract_payloads_per_flow(pcap_path: str) -> Dict[FlowKey, bytes]:
    """Read PCAP, group raw L7 payloads by canonical 5-tuple.

    Both directions (client->server, server->client) are concatenated into
    one blob per flow. Order within each direction is preserved by PCAP
    arrival order; cross-direction interleaving is not — which is fine
    for signature matching but would be wrong for protocol parsing.
    """
    try:
        from scapy.all import PcapReader, IP, IPv6, TCP, UDP, Raw
    except ImportError:
        logger.warning("scapy not available; YARA payload extraction skipped")
        return {}

    flows: Dict[FlowKey, List[bytes]] = defaultdict(list)
    sizes: Dict[FlowKey, int] = defaultdict(int)
    truncated: set = set()

    try:
        with PcapReader(pcap_path) as reader:
            for pkt in reader:
                if IP in pkt:
                    src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
                elif IPv6 in pkt:
                    src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst
                else:
                    continue

                if TCP in pkt:
                    src_port = int(pkt[TCP].sport)
                    dst_port = int(pkt[TCP].dport)
                    proto = 6
                elif UDP in pkt:
                    src_port = int(pkt[UDP].sport)
                    dst_port = int(pkt[UDP].dport)
                    proto = 17
                else:
                    continue

                if Raw not in pkt:
                    continue
                payload = bytes(pkt[Raw].load)
                if not payload:
                    continue

                key = _canonical_key(src_ip, dst_ip, src_port, dst_port, proto)
                if key in truncated:
                    continue
                if sizes[key] + len(payload) > _MAX_PAYLOAD_BYTES:
                    # Keep what fits to round out the cap, then mark as full.
                    remaining = _MAX_PAYLOAD_BYTES - sizes[key]
                    if remaining > 0:
                        flows[key].append(payload[:remaining])
                        sizes[key] = _MAX_PAYLOAD_BYTES
                    truncated.add(key)
                    continue
                flows[key].append(payload)
                sizes[key] += len(payload)
    except Exception as e:
        logger.warning("PCAP payload extraction failed for %s: %s", pcap_path, e)
        return {}

    return {k: b"".join(v) for k, v in flows.items()}


def scan_payloads(payload_map: Dict[FlowKey, bytes],
                  use_community: bool = False) -> Dict[FlowKey, Dict[str, float]]:
    """Run YARA on each flow's payload, return per-flow feature dict.

    Returns *only* flows that produced at least one match — callers should
    default the others to zeros. Custom rules tier first; community rules
    only run for flows where custom found nothing AND ``use_community`` is
    true (off by default — community has 500+ rules and triples scan time).
    """
    from threatlens.rules.signatures import (
        _compile_custom_rules,
        _compile_community_rules,
        HAS_YARA,
    )

    out: Dict[FlowKey, Dict[str, float]] = {}
    if not HAS_YARA or not payload_map:
        return out

    custom = _compile_custom_rules()
    community = _compile_community_rules() if use_community else None

    for key, payload in payload_map.items():
        if len(payload) < _MIN_PAYLOAD_BYTES:
            continue

        seen_rules = set()
        max_sev = 0.0

        def _consume(matches):
            nonlocal max_sev
            for m in matches:
                if m.rule in seen_rules:
                    continue
                seen_rules.add(m.rule)
                sev_str = m.meta.get("severity",
                                     m.meta.get("threat_level", "medium"))
                sev = _SEVERITY_SCORES.get(str(sev_str).lower(), 50.0)
                if sev > max_sev:
                    max_sev = sev

        if custom is not None:
            try:
                _consume(custom.match(data=payload,
                                      timeout=_YARA_TIMEOUT_S, fast=True))
            except Exception as e:
                logger.debug("YARA custom error for flow: %s", e)

        if community is not None and not seen_rules:
            try:
                _consume(community.match(data=payload,
                                         timeout=_YARA_TIMEOUT_S, fast=True))
            except Exception as e:
                logger.debug("YARA community error for flow: %s", e)

        if not seen_rules:
            continue

        out[key] = {
            "YARA Match Count": float(len(seen_rules)),
            "YARA Max Severity": float(max_sev),
            "YARA Has Match": 1.0,
        }

    return out


def compute_yara_features(pcap_path: str,
                          use_community: bool = False) -> Dict[FlowKey, Dict[str, float]]:
    """One-shot: PCAP path -> {canonical_5tuple: {YARA_col: value}}.

    Designed to be called once per PCAP and merged into the
    cicflowmeter-derived DataFrame by row lookup.
    """
    payloads = extract_payloads_per_flow(pcap_path)
    if not payloads:
        return {}
    return scan_payloads(payloads, use_community=use_community)
