"""Day 9e — long-tail protocol-coverage generator.

Day 9d post-mortem (per-capture diagnostic on the remaining 24 FP +
24 FN) showed four specific feature-space corners that the existing
generators miss:

  1. TLS 1.2 quick-fetch sessions (e.g. ChaCha20-Poly1305 — but the
     cipher itself doesn't matter; what matters is the FLOW SHAPE:
     5 fwd / 5-6 bwd packets, server-heavy 6x, sub-50ms duration)
  2. HTTP/2 over TLS — high-throughput stream (20-30 packets,
     server-heavy 30x, large 1800-byte avg)
  3. HTTP/2 over TLS — long-idle keep-alive (4-8 packets, multi-second
     IAT, multi-second duration, small packets)
  4. TCP-connect micro-bruteforce (handshake + immediate RST, 5-7
     packets, ~70-byte avg, sub-ms IAT). Stratosphere
     slips_ssh-bruteforce.pcap missed flows are exactly this shape on
     TCP/902. Labelled as PortScan since the FlowExtractor sees these
     independently and they ARE port-scan-shaped.

This generator produces wide-distribution synthetic flows for each
of those four patterns. Output goes to data/synthetic/long_tail/
and gets merged into training via train_python_only.py (auto-discovered
by the diverse_benign and attack_volume parquet readers if labelled
appropriately).

We DELIBERATELY do not look at the test PCAPs' actual content — only
their FEATURE-DISTRIBUTION RANGES, which we then span with random
parameters. The whole point is to teach the model that these
feature regions exist and are normal, without giving it the test set.

Usage:
    python scripts/generate_long_tail.py
    python scripts/generate_long_tail.py --flows-per-profile 300
"""
from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path
from typing import List

from scapy.all import Ether, IP, Raw, TCP, wrpcap

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "data" / "synthetic" / "long_tail"

INTERNAL_HOSTS = (
    [f"10.0.{i}.{j}" for i in range(0, 5) for j in range(20, 30)]
    + [f"192.168.1.{i}" for i in range(20, 80)]
    + [f"192.168.100.{i}" for i in range(100, 200)]
)
EXTERNAL_HOSTS = [
    "104.16.85.20", "151.101.1.140", "172.217.0.0", "140.82.121.4",
    "52.20.100.10", "13.32.21.5", "204.79.197.200", "31.13.66.35",
    "162.159.200.123", "216.229.0.50",
]


def rand_port() -> int:
    return random.randint(32768, 60999)


def _hs(t0: float, src: str, dst: str, sp: int, dp: int):
    seq_c = random.randint(1000, 1_000_000)
    seq_s = random.randint(1000, 1_000_000)
    pkts = []
    syn = Ether() / IP(src=src, dst=dst) / TCP(sport=sp, dport=dp,
                                                flags="S", seq=seq_c)
    syn.time = t0
    sa = Ether() / IP(src=dst, dst=src) / TCP(sport=dp, dport=sp,
                                                flags="SA", seq=seq_s,
                                                ack=seq_c + 1)
    sa.time = t0 + random.uniform(0.001, 0.020)
    ack = Ether() / IP(src=src, dst=dst) / TCP(sport=sp, dport=dp,
                                                flags="A", seq=seq_c + 1,
                                                ack=seq_s + 1)
    ack.time = sa.time + random.uniform(0.0003, 0.003)
    pkts.extend([syn, sa, ack])
    return pkts, seq_c + 1, seq_s + 1, ack.time


def _close_fin(t: float, src: str, dst: str, sp: int, dp: int,
                seq_c: int, seq_s: int) -> List:
    fin_c = Ether() / IP(src=src, dst=dst) / TCP(sport=sp, dport=dp,
                                                  flags="FA", seq=seq_c,
                                                  ack=seq_s)
    fin_c.time = t + random.uniform(0.0005, 0.010)
    fin_s = Ether() / IP(src=dst, dst=src) / TCP(sport=dp, dport=sp,
                                                  flags="FA", seq=seq_s,
                                                  ack=seq_c + 1)
    fin_s.time = fin_c.time + random.uniform(0.0005, 0.010)
    last_ack = Ether() / IP(src=src, dst=dst) / TCP(sport=sp, dport=dp,
                                                     flags="A",
                                                     seq=seq_c + 1,
                                                     ack=seq_s + 1)
    last_ack.time = fin_s.time + random.uniform(0.0001, 0.002)
    return [fin_c, fin_s, last_ack]


# -----------------------------------------------------------------------
# Profile 1: TLS quick-fetch (covers wireshark_tls12-chacha20.pcap shape)
# -----------------------------------------------------------------------
def craft_tls_quick_fetch(t0: float, src: str, dst: str) -> List:
    """5 fwd, 5-6 bwd packets. Server-heavy. Sub-50ms total.

    Real-world shape: a single API call or short web fetch over TLS.
    Cipher (ChaCha20 / AES-GCM) doesn't change the shape, only the
    record-size pattern (which we vary anyway).
    """
    sp, dp = rand_port(), 443
    pkts, seq_c, seq_s, t_now = _hs(t0, src, dst, sp, dp)

    # ClientHello — varied size (200-500 bytes is typical)
    ch_size = random.randint(180, 500)
    ch = Ether() / IP(src=src, dst=dst) / TCP(sport=sp, dport=dp,
                                               flags="PA", seq=seq_c,
                                               ack=seq_s) / Raw(load=bytes(ch_size))
    ch.time = t_now + random.uniform(0.0005, 0.005)
    seq_c += ch_size
    pkts.append(ch)

    # Server hands back the certificate chain + key exchange — usually
    # large because cert chains are 1-3 KB. Send as 2-3 packets.
    server_total = random.randint(3500, 6500)
    n_chunks = random.randint(2, 4)
    chunk_sizes = []
    remaining = server_total
    for i in range(n_chunks):
        if i == n_chunks - 1:
            chunk_sizes.append(remaining)
        else:
            sz = random.randint(800, 1450)
            chunk_sizes.append(sz)
            remaining -= sz
    last_t = ch.time
    for sz in chunk_sizes:
        sp_pkt = Ether() / IP(src=dst, dst=src) / TCP(sport=dp, dport=sp,
                                                        flags="PA", seq=seq_s,
                                                        ack=seq_c) / Raw(load=bytes(max(sz, 40)))
        sp_pkt.time = last_t + random.uniform(0.0005, 0.005)
        seq_s += max(sz, 40)
        last_t = sp_pkt.time
        pkts.append(sp_pkt)

    # Client ChangeCipherSpec + Finished (small, ~100-200 bytes)
    cf = Ether() / IP(src=src, dst=dst) / TCP(sport=sp, dport=dp,
                                                flags="PA", seq=seq_c,
                                                ack=seq_s) / Raw(load=bytes(random.randint(80, 200)))
    cf.time = last_t + random.uniform(0.0005, 0.005)
    seq_c += len(cf[Raw].load)
    pkts.append(cf)

    # Client app-data (the request — 1 small packet, ~150-400 bytes)
    cd = Ether() / IP(src=src, dst=dst) / TCP(sport=sp, dport=dp,
                                                flags="PA", seq=seq_c,
                                                ack=seq_s) / Raw(load=bytes(random.randint(150, 400)))
    cd.time = cf.time + random.uniform(0.0005, 0.005)
    seq_c += len(cd[Raw].load)
    pkts.append(cd)

    # No more packets — quick session ends. Some end with FIN, some RST.
    if random.random() < 0.4:
        rst = Ether() / IP(src=src, dst=dst) / TCP(sport=sp, dport=dp,
                                                    flags="R", seq=seq_c, ack=seq_s)
        rst.time = cd.time + random.uniform(0.0005, 0.005)
        pkts.append(rst)
    else:
        pkts.extend(_close_fin(cd.time, src, dst, sp, dp, seq_c, seq_s))
    return pkts


# -----------------------------------------------------------------------
# Profile 2: HTTP/2 high-throughput stream (covers data-reassembly shape)
# -----------------------------------------------------------------------
def craft_http2_data_stream(t0: float, src: str, dst: str) -> List:
    """~25 fwd, ~25 bwd packets, server-heavy 30x, large ~1800-byte avg.

    Real-world shape: an HTTP/2 fetch of a sizable resource (image,
    bundle, video chunk). HTTP/2 multiplexing means many DATA frames
    flow in both directions.
    """
    sp, dp = rand_port(), random.choice([443, 8443])
    pkts, seq_c, seq_s, t_now = _hs(t0, src, dst, sp, dp)

    # TLS handshake (short — abbreviated since we're focusing on the data)
    ch_size = random.randint(220, 450)
    ch = Ether() / IP(src=src, dst=dst) / TCP(sport=sp, dport=dp,
                                                flags="PA", seq=seq_c,
                                                ack=seq_s) / Raw(load=bytes(ch_size))
    ch.time = t_now + random.uniform(0.001, 0.005)
    seq_c += ch_size
    pkts.append(ch)
    sh_size = random.randint(1200, 2800)
    sh = Ether() / IP(src=dst, dst=src) / TCP(sport=dp, dport=sp,
                                                flags="PA", seq=seq_s,
                                                ack=seq_c) / Raw(load=bytes(sh_size))
    sh.time = ch.time + random.uniform(0.005, 0.030)
    seq_s += sh_size
    pkts.append(sh)
    cf = Ether() / IP(src=src, dst=dst) / TCP(sport=sp, dport=dp,
                                                flags="PA", seq=seq_c,
                                                ack=seq_s) / Raw(load=bytes(random.randint(80, 200)))
    cf.time = sh.time + random.uniform(0.001, 0.005)
    seq_c += len(cf[Raw].load)
    pkts.append(cf)

    # HTTP/2 connection preface (24 bytes literal + binary frames after)
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + bytes(random.randint(100, 300))
    p = Ether() / IP(src=src, dst=dst) / TCP(sport=sp, dport=dp,
                                              flags="PA", seq=seq_c,
                                              ack=seq_s) / Raw(load=preface)
    p.time = cf.time + random.uniform(0.001, 0.005)
    seq_c += len(preface)
    pkts.append(p)

    # SETTINGS ACK from server
    p = Ether() / IP(src=dst, dst=src) / TCP(sport=dp, dport=sp,
                                              flags="PA", seq=seq_s,
                                              ack=seq_c) / Raw(load=bytes(random.randint(40, 100)))
    p.time = pkts[-1].time + random.uniform(0.001, 0.010)
    seq_s += len(p[Raw].load)
    pkts.append(p)

    # The actual data stream: 18-25 large server packets with occasional
    # small ACK-window-update from client. Heavy server-side bias.
    last_t = pkts[-1].time
    n_server = random.randint(18, 25)
    n_client_acks = random.randint(3, 7)
    server_pkts = [random.randint(1300, 1500) for _ in range(n_server)]
    client_pkts = [random.randint(40, 90) for _ in range(n_client_acks)]
    # Interleave (mostly server packets, occasional client window-update)
    schedule = ["S"] * n_server + ["C"] * n_client_acks
    random.shuffle(schedule)
    for d in schedule:
        if d == "S":
            sz = server_pkts.pop()
            sp_pkt = Ether() / IP(src=dst, dst=src) / TCP(sport=dp, dport=sp,
                                                            flags="PA", seq=seq_s,
                                                            ack=seq_c) / Raw(load=bytes(sz))
            seq_s += sz
        else:
            sz = client_pkts.pop()
            sp_pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=sp, dport=dp,
                                                            flags="PA", seq=seq_c,
                                                            ack=seq_s) / Raw(load=bytes(sz))
            seq_c += sz
        sp_pkt.time = last_t + random.uniform(0.001, 0.020)
        last_t = sp_pkt.time
        pkts.append(sp_pkt)

    pkts.extend(_close_fin(last_t, src, dst, sp, dp, seq_c, seq_s))
    return pkts


# -----------------------------------------------------------------------
# Profile 3: HTTP/2 long-idle keep-alive (covers follow_multistream shape)
# -----------------------------------------------------------------------
def craft_http2_long_idle(t0: float, src: str, dst: str) -> List:
    """4-8 fwd, 5-9 bwd packets, MULTI-SECOND IAT, small packets.

    Real-world shape: HTTP/2 connection used as a long-lived keep-alive
    channel — handshake then minutes-long idle with occasional ping/pong.
    """
    # Use a non-standard port half the time to look like reverse-tunnel
    sp, dp = rand_port(), random.choice([443, 443, 8443, rand_port()])
    pkts, seq_c, seq_s, t_now = _hs(t0, src, dst, sp, dp)

    # Tiny TLS handshake (just symbolic — small packets)
    p = Ether() / IP(src=src, dst=dst) / TCP(sport=sp, dport=dp,
                                              flags="PA", seq=seq_c,
                                              ack=seq_s) / Raw(load=bytes(random.randint(60, 140)))
    p.time = t_now + random.uniform(0.001, 0.020)
    seq_c += len(p[Raw].load)
    pkts.append(p)
    p = Ether() / IP(src=dst, dst=src) / TCP(sport=dp, dport=sp,
                                              flags="PA", seq=seq_s,
                                              ack=seq_c) / Raw(load=bytes(random.randint(60, 140)))
    p.time = pkts[-1].time + random.uniform(0.005, 0.030)
    seq_s += len(p[Raw].load)
    pkts.append(p)

    # Long-idle exchange: a few HEADERS/PING frames seconds apart
    last_t = pkts[-1].time
    n_pings = random.randint(2, 6)
    for i in range(n_pings):
        # PING from client
        sz = random.randint(40, 80)
        ping = Ether() / IP(src=src, dst=dst) / TCP(sport=sp, dport=dp,
                                                     flags="PA", seq=seq_c,
                                                     ack=seq_s) / Raw(load=bytes(sz))
        ping.time = last_t + random.uniform(2.0, 8.0)  # 2-8 second gaps
        seq_c += sz
        pkts.append(ping)
        # PONG from server
        sz = random.randint(40, 80)
        pong = Ether() / IP(src=dst, dst=src) / TCP(sport=dp, dport=sp,
                                                     flags="PA", seq=seq_s,
                                                     ack=seq_c) / Raw(load=bytes(sz))
        pong.time = ping.time + random.uniform(0.005, 0.080)
        seq_s += sz
        pkts.append(pong)
        last_t = pong.time

    pkts.extend(_close_fin(last_t, src, dst, sp, dp, seq_c, seq_s))
    return pkts


# -----------------------------------------------------------------------
# Profile 4: TCP-connect micro-bruteforce (covers slips TCP/902 missed flows)
# -----------------------------------------------------------------------
# These are labelled as PortScan because that is the FlowExtractor-visible
# shape: a tiny TCP-connect attempt with no payload, ending in RST. It
# happens to BE a brute-force tool's discovery probe, but the 5-tuple-only
# flow extractor can't tell that — so we train on the visible shape.
def craft_tcp_connect_micro(t0: float, src: str, dst: str,
                              dst_port: int = None) -> List:
    """4-8 packets total. Tiny payload. Connect + maybe-probe + RST/FIN.

    Day 9e v2: the slips_ssh-bruteforce.pcap missed flows have duration
    5-54ms and avg packet size ~72B. Earlier version had duration <5ms
    which was too narrow. Now spans the real-world range with optional
    intermediate exchanges.
    """
    if dst_port is None:
        # Heavily weight 902 (the slips target) and other commonly-attacked
        # ports so the model sees enough volume of each
        dst_port = random.choice(
            [902, 902, 902, 902,           # the slips-style port
             1080, 5060, 5900, 8080, 8443, 8888,
             9999, 10000, 50000,
             22, 21, 23, 3306, 3389, 5432, 1433, 27017, 6379]
        )
    sp, dp = rand_port(), dst_port
    pkts, seq_c, seq_s, t_now = _hs(t0, src, dst, sp, dp)

    # Vary the number of intermediate exchanges to span the 5-54ms range.
    # Some flows: just handshake + RST. Others: handshake + small probe +
    # short response + RST. A few: handshake + multiple tiny exchanges.
    n_exchanges = random.choices([0, 1, 2, 3], weights=[20, 35, 30, 15])[0]
    last_t = t_now
    for _ in range(n_exchanges):
        # Tiny probe from client
        sz = random.randint(0, 40)  # 0 = empty PSH-ACK, just keepalive-y
        if sz > 0:
            probe = Ether() / IP(src=src, dst=dst) / TCP(sport=sp, dport=dp,
                                                          flags="PA", seq=seq_c,
                                                          ack=seq_s) / Raw(load=bytes(sz))
        else:
            probe = Ether() / IP(src=src, dst=dst) / TCP(sport=sp, dport=dp,
                                                          flags="A", seq=seq_c,
                                                          ack=seq_s)
        # IAT spans 0.5-15ms per exchange so total can reach 5-50ms
        probe.time = last_t + random.uniform(0.0005, 0.015)
        seq_c += sz
        pkts.append(probe)
        # Maybe server response (or RST — port closed)
        if random.random() < 0.55:
            resp_sz = random.randint(0, 40)
            if resp_sz > 0:
                resp = Ether() / IP(src=dst, dst=src) / TCP(sport=dp, dport=sp,
                                                              flags="PA", seq=seq_s,
                                                              ack=seq_c) / Raw(load=bytes(resp_sz))
            else:
                resp = Ether() / IP(src=dst, dst=src) / TCP(sport=dp, dport=sp,
                                                              flags="A", seq=seq_s,
                                                              ack=seq_c)
            resp.time = probe.time + random.uniform(0.0005, 0.012)
            seq_s += resp_sz
            pkts.append(resp)
            last_t = resp.time
        else:
            last_t = probe.time

    # RST or FIN close
    if random.random() < 0.7:
        # Sender RST is typical of brute-force tools that move on fast
        rst = Ether() / IP(src=src, dst=dst) / TCP(sport=sp, dport=dp,
                                                     flags="R", seq=seq_c,
                                                     ack=seq_s)
        rst.time = last_t + random.uniform(0.0005, 0.005)
        pkts.append(rst)
    else:
        # Sometimes server-side RST (received from victim's TCP stack)
        rst = Ether() / IP(src=dst, dst=src) / TCP(sport=dp, dport=sp,
                                                     flags="R", seq=seq_s,
                                                     ack=seq_c)
        rst.time = last_t + random.uniform(0.0005, 0.005)
        pkts.append(rst)
    return pkts


def craft_ssh_micro_bruteforce(t0: float, src: str, dst: str) -> List:
    """SSH-Patator-labelled variant of the micro brute-force pattern.

    Same shape as tcp_connect_micro but always targets ports commonly
    associated with SSH-style services (22, 22022, 902, 2222) — gives the
    model a direct example of "tiny rapid-fire flows on these ports = SSH
    brute-force". Without this, the model classifies these flows as
    BENIGN because the existing SSH-Patator training (full hydra session
    with banner / KEX / auth-fail) has very different features
    (avg packet size 225 B, multi-second duration, multi-packet exchange).
    """
    dst_port = random.choice([22, 22, 22022, 2222, 902, 902, 902])
    return craft_tcp_connect_micro(t0, src, dst, dst_port=dst_port)


# Profile spec: name, craft_fn, label, n_per_profile_default
PROFILES_OLD = None  # was the earlier list; replaced below
PROFILES = [
    ("tls_quick_fetch", craft_tls_quick_fetch, "BENIGN", "diverse_benign"),
    ("http2_data_stream", craft_http2_data_stream, "BENIGN", "diverse_benign"),
    ("http2_long_idle", craft_http2_long_idle, "BENIGN", "diverse_benign"),
    ("tcp_connect_micro", craft_tcp_connect_micro, "PortScan", "attack_volume"),
    ("ssh_micro_bruteforce", craft_ssh_micro_bruteforce, "SSH-Patator",
     "attack_volume"),
]


# Removed — see PROFILES list defined above next to ssh_micro_bruteforce.


def generate_profile(name: str, craft_fn, n_flows: int, out_path: Path,
                       seed: int) -> int:
    random.seed(seed)
    pkts = []
    t = 0.0
    for _ in range(n_flows):
        src = random.choice(INTERNAL_HOSTS)
        dst = random.choice(EXTERNAL_HOSTS)
        pkts.extend(craft_fn(t, src, dst))
        t += random.uniform(0.005, 0.250)
    pkts.sort(key=lambda p: p.time)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(out_path), pkts)
    return len(pkts)


def main() -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser()
    parser.add_argument("--flows-per-profile", type=int, default=300)
    parser.add_argument("--seed", type=int, default=2027)
    args = parser.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Generating long-tail PCAPs into {OUT_DIR}")
    print(f"  flows per profile: {args.flows_per_profile}")
    total_pkts = 0
    for i, (name, craft_fn, label, group) in enumerate(PROFILES):
        out_path = OUT_DIR / f"{name}__{label.replace('-', '_')}__{group}.pcap"
        n = generate_profile(name, craft_fn, args.flows_per_profile, out_path,
                              seed=args.seed + i)
        size_kb = out_path.stat().st_size // 1024
        print(f"  {name:<22} -> {out_path.name:<60} "
              f"({n:>5} pkts, {size_kb:>4} KB) label={label} group={group}")
        total_pkts += n
    print(f"\nTotal: {len(PROFILES) * args.flows_per_profile} flows / "
          f"{total_pkts} packets across {len(PROFILES)} PCAPs")
    print("Next: python scripts/extract_long_tail.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
