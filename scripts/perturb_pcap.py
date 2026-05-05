"""Phase 3 — adversarial PCAP perturbator.

Reads a PCAP and emits a perturbed copy with a chosen evasion technique
applied at one of four strength levels. Used by `adversarial_eval.py`
to measure how recall degrades against simple traffic-shaping evasion —
the kind a defender should expect any motivated attacker to attempt.

Perturbations are deliberately *naive* — they don't try to be smart
mimicry, just basic shape-changing that preserves wire-level validity:

  iat_jitter      Gaussian noise on inter-packet timing (keeps order)
  packet_padding  Append random bytes to TCP/UDP payload (keeps headers)
  ttl_random      Randomise IP TTL per packet
  rst_inject      Insert spurious RST after random ACK (rate-limited)

Rejected on the design phase (would break PCAP validity or change the
flow's 5-tuple identity, which would conflate evasion with feature
extraction failure):

  - tls_handshake_reorder   Re-orders TLS records, breaks decryption
                            assumptions in some parsers
  - frag_syn                IP fragmentation often dropped by NIC offload
                            and changes packet count semantics

Strength levels (configurable per perturbation):

  none      passthrough (sanity check)
  mild      barely visible — should drop recall <5 pp if model robust
  moderate  obvious to a human looking at the PCAP — should drop 5-15 pp
  aggressive crude evasion — recall drop >15 pp tells us the feature is
            timing-fragile

Validity contract:
  - Output PCAP is parseable by FlowExtractor
  - Output flows have the same 5-tuple identity as input flows
    (same src/dst IP+port+protocol)
  - Packet count per flow is preserved (no add / drop, except rst_inject
    which is documented to add)
  - IP / TCP / UDP checksums are recomputed by scapy on serialisation

Usage:
    python scripts/perturb_pcap.py \\
        --in data/sandbox_malware/stratosphere/CTU-Mixed-Capture-6__bot__Bot.pcap \\
        --out /tmp/mixed6_jittered.pcap \\
        --perturbation iat_jitter --strength moderate
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Optional

import numpy as np

# scapy is loud about no-libpcap on Windows; suppress the import-time noise
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="scapy")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

logger = logging.getLogger("perturb_pcap")


PERTURBATIONS = ("iat_jitter", "packet_padding", "ttl_random", "rst_inject")
STRENGTH_LEVELS = ("none", "mild", "moderate", "aggressive")

# Per-perturbation strength tables. None = passthrough.
JITTER_SIGMA_US = {            # Gaussian noise stddev on packet timestamp
    "none": 0,
    "mild":      1_000,        # 1 ms
    "moderate": 10_000,        # 10 ms
    "aggressive": 100_000,     # 100 ms
}
PADDING_BYTES = {              # uniform random additional payload per packet
    "none": (0, 0),
    "mild": (10, 50),
    "moderate": (50, 200),
    "aggressive": (200, 500),
}
TTL_NOISE = {                  # ±delta clipped to [1, 255]
    "none": 0,
    "mild": 5,
    "moderate": 20,
    "aggressive": 50,
}
RST_INJECT_RATE = {            # fraction of ACK packets that get a spurious RST after them
    "none": 0.0,
    "mild": 0.01,
    "moderate": 0.05,
    "aggressive": 0.20,
}


def apply_iat_jitter(packets, sigma_us: int, seed: int):
    """Add Gaussian noise to inter-packet timing. Preserves order."""
    if sigma_us <= 0:
        return packets
    rng = np.random.default_rng(seed)
    if not packets:
        return packets
    base_t = packets[0].time
    rel = [float(p.time) - float(base_t) for p in packets]
    # Jitter relative timestamps; force monotonic
    jittered = []
    last = 0.0
    for r in rel:
        noise_s = rng.normal(0.0, sigma_us / 1_000_000.0)
        new_r = max(last + 1e-6, r + noise_s)  # 1 us minimum gap
        jittered.append(new_r)
        last = new_r
    for p, new_r in zip(packets, jittered):
        p.time = base_t + new_r
    return packets


def apply_packet_padding(packets, lo: int, hi: int, seed: int):
    """Append random bytes to TCP/UDP payload. Preserves 5-tuple."""
    from scapy.all import Raw, TCP, UDP
    if hi <= 0:
        return packets
    rng = np.random.default_rng(seed)
    out = []
    for p in packets:
        # Only pad packets that already carry a transport layer
        if p.haslayer(TCP) or p.haslayer(UDP):
            n_pad = int(rng.integers(lo, hi + 1))
            if n_pad > 0:
                pad_bytes = bytes(rng.integers(0, 256, n_pad).tolist())
                # Either extend existing Raw or append new Raw
                if p.haslayer(Raw):
                    p[Raw].load = p[Raw].load + pad_bytes
                else:
                    p = p / Raw(load=pad_bytes)
                # Reset cached lengths/checksums so scapy recomputes
                if p.haslayer(TCP):
                    del p[TCP].chksum
                if p.haslayer(UDP):
                    del p[UDP].chksum
                    del p[UDP].len
                if hasattr(p, "len"):
                    del p.len
        out.append(p)
    return out


def apply_ttl_random(packets, delta: int, seed: int):
    """Add ±delta noise to IP TTL field."""
    from scapy.all import IP
    if delta <= 0:
        return packets
    rng = np.random.default_rng(seed)
    for p in packets:
        if p.haslayer(IP):
            base = p[IP].ttl
            noise = int(rng.integers(-delta, delta + 1))
            p[IP].ttl = int(np.clip(base + noise, 1, 255))
            del p[IP].chksum
    return packets


def apply_rst_inject(packets, rate: float, seed: int):
    """Insert spurious TCP RST after a fraction of ACK packets."""
    from scapy.all import IP, TCP
    if rate <= 0:
        return packets
    rng = np.random.default_rng(seed)
    out = []
    for p in packets:
        out.append(p)
        if (rate > 0 and p.haslayer(TCP) and p.haslayer(IP)
                and p[TCP].flags & 0x10  # ACK
                and rng.random() < rate):
            # Build a RST in the same direction
            rst = IP(src=p[IP].src, dst=p[IP].dst,
                     ttl=p[IP].ttl) / TCP(
                sport=p[TCP].sport, dport=p[TCP].dport,
                flags="R",
                seq=p[TCP].seq + (len(p[TCP].payload) if p[TCP].payload else 0),
            )
            rst.time = float(p.time) + 1e-5  # +10 us
            out.append(rst)
    return out


PERTURBATION_FNS = {
    "iat_jitter": lambda packets, strength, seed:
        apply_iat_jitter(packets, JITTER_SIGMA_US[strength], seed),
    "packet_padding": lambda packets, strength, seed:
        apply_packet_padding(packets, *PADDING_BYTES[strength], seed),
    "ttl_random": lambda packets, strength, seed:
        apply_ttl_random(packets, TTL_NOISE[strength], seed),
    "rst_inject": lambda packets, strength, seed:
        apply_rst_inject(packets, RST_INJECT_RATE[strength], seed),
}


def perturb(in_path: Path, out_path: Path, perturbation: str,
             strength: str, seed: int = 42) -> int:
    """Apply one perturbation to one PCAP. Returns 0 on success."""
    from scapy.all import rdpcap, wrpcap, Ether, IP, IPv6, Raw
    if perturbation not in PERTURBATION_FNS:
        raise ValueError(f"unknown perturbation: {perturbation}")
    if strength not in STRENGTH_LEVELS:
        raise ValueError(f"unknown strength: {strength}")
    logger.info("Reading %s", in_path.name)
    packets_raw = list(rdpcap(str(in_path)))
    n_raw = len(packets_raw)

    # Filter out Raw frames at PCAP start (some captures have truncated/
    # malformed leading frames that scapy can't classify; mixing them with
    # Ether/IP packets confuses wrpcap's linktype selection).
    packets = [p for p in packets_raw
                if (p.haslayer(Ether) or p.haslayer(IP) or p.haslayer(IPv6))]
    n_filtered = n_raw - len(packets)
    if n_filtered > 0:
        logger.info("  filtered %d non-classifiable packets", n_filtered)
    logger.info("  %d packets ready (was %d)", len(packets), n_raw)

    if strength != "none":
        packets = PERTURBATION_FNS[perturbation](packets, strength, seed)
    n_out = len(packets)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    # Force linktype=1 (DLT_EN10MB / Ethernet) since FlowExtractor expects it
    wrpcap(str(out_path), packets, linktype=1)
    logger.info("Wrote %s  (raw=%d -> in=%d -> out=%d, perturbation=%s strength=%s)",
                out_path.name, n_raw, len(packets), n_out, perturbation, strength)
    return 0


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--in", dest="in_path", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--perturbation", choices=PERTURBATIONS, required=True)
    p.add_argument("--strength", choices=STRENGTH_LEVELS, required=True)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--verbose", "-v", action="count", default=0)
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                         format="%(levelname)-7s %(message)s")
    return perturb(args.in_path, args.out, args.perturbation,
                    args.strength, args.seed)


if __name__ == "__main__":
    sys.exit(main())
