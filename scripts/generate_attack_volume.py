"""Day 9d — high-volume attack PCAP generator.

Day 9 result: ``slips_ssh-bruteforce.pcap`` recall is 58.2 %
(39 / 67 attack flows). Root cause: training has only 27 SSH-Patator
samples and 48 FTP-Patator samples — the model learns the class label
exists but can't generalise.

This script crafts hydra-style SSH and FTP brute-force PCAPs at scale
(~600 distinct connection attempts per protocol). Each connection
attempt is a separate 5-tuple, so the FlowExtractor counts each as a
separate flow. After re-training, the per-class counts go from
27 / 48 to 600+ / 600+ — enough for the model to actually learn the
"many short auth-fail flows in rapid succession" pattern.

Profiles:
  ssh_bruteforce_v1 - same-source-IP, different src ports, dst:22
                      (single attacker doing parallel SSH attempts)
  ssh_bruteforce_v2 - distributed source IPs, dst:22
                      (botnet-style coordinated brute-force)
  ftp_bruteforce_v1 - same-source-IP, different src ports, dst:21
  ftp_bruteforce_v2 - distributed FTP brute-force

Each profile generates ~300 attempts, total ~1200 new attack flows.

Usage:
    python scripts/generate_attack_volume.py
    python scripts/generate_attack_volume.py --attempts-per-profile 500
"""
from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path
from typing import List

from scapy.all import Ether, IP, Raw, TCP, wrpcap

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "data" / "synthetic" / "attack_volume"

# Realistic SSH banners
SSH_SERVER_BANNERS = [
    b"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1\r\n",
    b"SSH-2.0-OpenSSH_7.4\r\n",
    b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n",
    b"SSH-2.0-OpenSSH_9.3\r\n",
]
SSH_CLIENT_BANNERS = [
    b"SSH-2.0-libssh_0.10.4\r\n",
    b"SSH-2.0-paramiko_2.12.0\r\n",
    b"SSH-2.0-Hydra\r\n",  # actual hydra fingerprint
    b"SSH-2.0-Medusa\r\n",
]


def rand_port() -> int:
    return random.randint(32768, 60999)


def _tcp_handshake(t0: float, src: str, dst: str, sp: int, dp: int):
    seq_c = random.randint(1000, 1_000_000)
    seq_s = random.randint(1000, 1_000_000)
    syn = (Ether() / IP(src=src, dst=dst) /
            TCP(sport=sp, dport=dp, flags="S", seq=seq_c))
    syn.time = t0
    sa = (Ether() / IP(src=dst, dst=src) /
            TCP(sport=dp, dport=sp, flags="SA", seq=seq_s, ack=seq_c + 1))
    sa.time = t0 + random.uniform(0.001, 0.030)
    ack = (Ether() / IP(src=src, dst=dst) /
            TCP(sport=sp, dport=dp, flags="A", seq=seq_c + 1, ack=seq_s + 1))
    ack.time = sa.time + random.uniform(0.0005, 0.005)
    return [syn, sa, ack], seq_c + 1, seq_s + 1, ack.time


def _tcp_rst(t: float, src: str, dst: str, sp: int, dp: int, seq: int, ack: int):
    rst = (Ether() / IP(src=src, dst=dst) /
            TCP(sport=sp, dport=dp, flags="R", seq=seq, ack=ack))
    rst.time = t + random.uniform(0.0005, 0.010)
    return rst


# Day 9d v2: SSH brute-force isn't always on TCP/22. Stratosphere
# slips_ssh-bruteforce.pcap targets TCP/902 (VMware Auth). Real-world
# brute-force tools also hit alt-ssh (2222, 22022), generic services
# (902, 1080, 8080, 9999), and DB ports (3306, 5432). Train across
# the full range so the *flow shape* (rapid short auth-fail flows)
# is the discriminator, not the literal port number.
SSH_BRUTEFORCE_PORTS = [22, 22, 22, 2222, 22022, 902, 8080, 9999,
                          3306, 5432, 1433, 3389]
FTP_BRUTEFORCE_PORTS = [21, 21, 21, 2121, 990, 8021, 10021]


def craft_ssh_attempt(t0: float, src: str, dst: str,
                       dst_port: int = None) -> List:
    """One SSH brute-force attempt: handshake + banner + KEX + auth fail + RST."""
    sp = rand_port()
    dp = dst_port if dst_port is not None else random.choice(SSH_BRUTEFORCE_PORTS)
    pkts, seq_c, seq_s, t_now = _tcp_handshake(t0, src, dst, sp, dp)
    # Server banner
    sb = random.choice(SSH_SERVER_BANNERS)
    p = (Ether() / IP(src=dst, dst=src) /
          TCP(sport=dp, dport=sp, flags="PA", seq=seq_s, ack=seq_c) /
          Raw(load=sb))
    p.time = t_now + random.uniform(0.005, 0.030)
    seq_s += len(sb)
    pkts.append(p)
    # ACK
    a = (Ether() / IP(src=src, dst=dst) /
          TCP(sport=sp, dport=dp, flags="A", seq=seq_c, ack=seq_s))
    a.time = p.time + random.uniform(0.0005, 0.005)
    pkts.append(a)
    # Client banner
    cb = random.choice(SSH_CLIENT_BANNERS)
    p = (Ether() / IP(src=src, dst=dst) /
          TCP(sport=sp, dport=dp, flags="PA", seq=seq_c, ack=seq_s) /
          Raw(load=cb))
    p.time = a.time + random.uniform(0.001, 0.010)
    seq_c += len(cb)
    pkts.append(p)
    # KEXINIT exchange (a few packets, ~700-1100 bytes each)
    last_t = p.time
    for i in range(random.randint(2, 4)):
        if i % 2 == 0:
            pl = bytes(random.randint(700, 1100))
            kp = (Ether() / IP(src=src, dst=dst) /
                   TCP(sport=sp, dport=dp, flags="PA", seq=seq_c, ack=seq_s) /
                   Raw(load=pl))
            seq_c += len(pl)
        else:
            pl = bytes(random.randint(700, 1100))
            kp = (Ether() / IP(src=dst, dst=src) /
                   TCP(sport=dp, dport=sp, flags="PA", seq=seq_s, ack=seq_c) /
                   Raw(load=pl))
            seq_s += len(pl)
        kp.time = last_t + random.uniform(0.005, 0.080)
        last_t = kp.time
        pkts.append(kp)
    # Auth attempt (short, encrypted)
    auth_req = bytes(random.randint(80, 200))
    p = (Ether() / IP(src=src, dst=dst) /
          TCP(sport=sp, dport=dp, flags="PA", seq=seq_c, ack=seq_s) /
          Raw(load=auth_req))
    p.time = last_t + random.uniform(0.020, 0.150)
    seq_c += len(auth_req)
    pkts.append(p)
    # Auth fail response
    auth_fail = bytes(random.randint(50, 90))
    p = (Ether() / IP(src=dst, dst=src) /
          TCP(sport=dp, dport=sp, flags="PA", seq=seq_s, ack=seq_c) /
          Raw(load=auth_fail))
    p.time = pkts[-1].time + random.uniform(0.030, 0.300)
    seq_s += len(auth_fail)
    pkts.append(p)
    # RST or FIN to close
    if random.random() < 0.6:
        pkts.append(_tcp_rst(pkts[-1].time, src, dst, sp, dp, seq_c, seq_s))
    else:
        # FIN-ACK exchange
        fin_c = (Ether() / IP(src=src, dst=dst) /
                  TCP(sport=sp, dport=dp, flags="FA", seq=seq_c, ack=seq_s))
        fin_c.time = pkts[-1].time + random.uniform(0.001, 0.020)
        fin_s = (Ether() / IP(src=dst, dst=src) /
                  TCP(sport=dp, dport=sp, flags="FA", seq=seq_s, ack=seq_c + 1))
        fin_s.time = fin_c.time + random.uniform(0.001, 0.020)
        pkts.extend([fin_c, fin_s])
    return pkts


def craft_ftp_attempt(t0: float, src: str, dst: str,
                       dst_port: int = None) -> List:
    """One FTP brute-force attempt: handshake + 220 banner + USER/PASS + 530 fail."""
    sp = rand_port()
    dp = dst_port if dst_port is not None else random.choice(FTP_BRUTEFORCE_PORTS)
    pkts, seq_c, seq_s, t_now = _tcp_handshake(t0, src, dst, sp, dp)
    # 220 banner
    banner = random.choice([
        b"220 ProFTPD Server (Debian)\r\n",
        b"220 vsftpd 3.0.3\r\n",
        b"220 (vsFTPd 3.0.5)\r\n",
        b"220 Welcome to FTP service.\r\n",
    ])
    p = (Ether() / IP(src=dst, dst=src) /
          TCP(sport=dp, dport=sp, flags="PA", seq=seq_s, ack=seq_c) /
          Raw(load=banner))
    p.time = t_now + random.uniform(0.005, 0.030)
    seq_s += len(banner)
    pkts.append(p)
    # USER cmd
    user = random.choice(["root", "admin", "test", "user", "ftp", "anonymous"])
    user_cmd = f"USER {user}\r\n".encode()
    p = (Ether() / IP(src=src, dst=dst) /
          TCP(sport=sp, dport=dp, flags="PA", seq=seq_c, ack=seq_s) /
          Raw(load=user_cmd))
    p.time = pkts[-1].time + random.uniform(0.005, 0.080)
    seq_c += len(user_cmd)
    pkts.append(p)
    # 331 password required
    resp = b"331 Please specify the password.\r\n"
    p = (Ether() / IP(src=dst, dst=src) /
          TCP(sport=dp, dport=sp, flags="PA", seq=seq_s, ack=seq_c) /
          Raw(load=resp))
    p.time = pkts[-1].time + random.uniform(0.010, 0.100)
    seq_s += len(resp)
    pkts.append(p)
    # PASS attempt
    pw = random.choice(["123456", "admin", "password", "letmein", "qwerty"])
    pass_cmd = f"PASS {pw}\r\n".encode()
    p = (Ether() / IP(src=src, dst=dst) /
          TCP(sport=sp, dport=dp, flags="PA", seq=seq_c, ack=seq_s) /
          Raw(load=pass_cmd))
    p.time = pkts[-1].time + random.uniform(0.005, 0.080)
    seq_c += len(pass_cmd)
    pkts.append(p)
    # 530 login failed (after a small delay — server intentionally slow)
    fail = b"530 Login incorrect.\r\n"
    p = (Ether() / IP(src=dst, dst=src) /
          TCP(sport=dp, dport=sp, flags="PA", seq=seq_s, ack=seq_c) /
          Raw(load=fail))
    p.time = pkts[-1].time + random.uniform(0.500, 1.500)  # rate-limit pause
    seq_s += len(fail)
    pkts.append(p)
    # Close
    if random.random() < 0.5:
        pkts.append(_tcp_rst(pkts[-1].time, src, dst, sp, dp, seq_c, seq_s))
    else:
        fin_c = (Ether() / IP(src=src, dst=dst) /
                  TCP(sport=sp, dport=dp, flags="FA", seq=seq_c, ack=seq_s))
        fin_c.time = pkts[-1].time + random.uniform(0.005, 0.030)
        fin_s = (Ether() / IP(src=dst, dst=src) /
                  TCP(sport=dp, dport=sp, flags="FA", seq=seq_s, ack=seq_c + 1))
        fin_s.time = fin_c.time + random.uniform(0.001, 0.020)
        pkts.extend([fin_c, fin_s])
    return pkts


def generate_concentrated(craft_fn, n_attempts: int, dst: str, label: str,
                            out_path: Path, seed: int) -> int:
    """Same-source brute-force (single attacker, hydra-style)."""
    random.seed(seed)
    src = f"192.168.100.{random.randint(50, 200)}"
    pkts = []
    t = 0.0
    for _ in range(n_attempts):
        pkts.extend(craft_fn(t, src, dst))
        # Hydra runs fast — small inter-attempt delay
        t += random.uniform(0.005, 0.080)
    pkts.sort(key=lambda p: p.time)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(out_path), pkts)
    return len(pkts)


def generate_distributed(craft_fn, n_attempts: int, dst: str, label: str,
                          out_path: Path, seed: int) -> int:
    """Distributed brute-force (botnet-style, varied source IPs)."""
    random.seed(seed)
    pkts = []
    t = 0.0
    src_pool = [f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
                 for _ in range(60)]
    for _ in range(n_attempts):
        src = random.choice(src_pool)
        pkts.extend(craft_fn(t, src, dst))
        # Distributed comes from multiple bots — slower per-source rate but
        # still bursty in aggregate
        t += random.uniform(0.020, 0.300)
    pkts.sort(key=lambda p: p.time)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(out_path), pkts)
    return len(pkts)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attempts-per-profile", type=int, default=300,
                        help="Connection attempts per PCAP (default 300)")
    parser.add_argument("--seed", type=int, default=1337)
    args = parser.parse_args()

    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Generating high-volume attack PCAPs into {OUT_DIR}")
    print(f"  attempts per profile: {args.attempts_per_profile}")

    plan = [
        ("ssh_bruteforce_concentrated", craft_ssh_attempt, "192.168.100.10",
         "SSH-Patator", generate_concentrated),
        ("ssh_bruteforce_distributed", craft_ssh_attempt, "192.168.100.10",
         "SSH-Patator", generate_distributed),
        ("ftp_bruteforce_concentrated", craft_ftp_attempt, "192.168.100.10",
         "FTP-Patator", generate_concentrated),
        ("ftp_bruteforce_distributed", craft_ftp_attempt, "192.168.100.10",
         "FTP-Patator", generate_distributed),
    ]

    total_pkts = 0
    for i, (name, craft_fn, dst, label, gen_fn) in enumerate(plan):
        out_path = OUT_DIR / f"{name}__{label.replace('-', '_')}.pcap"
        n_pkts = gen_fn(craft_fn, args.attempts_per_profile, dst, label, out_path,
                        seed=args.seed + i)
        size_kb = out_path.stat().st_size // 1024
        print(f"  {name:<32} -> {out_path.name:<55} "
              f"({n_pkts:>5} pkts, {size_kb:>4} KB, label={label})")
        total_pkts += n_pkts

    print(f"\nTotal: {len(plan) * args.attempts_per_profile} attempts / "
          f"{total_pkts} packets across {len(plan)} PCAPs")
    print("Next: python scripts/extract_attack_volume.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
