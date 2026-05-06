"""Phase 2 — external benchmark vs Suricata + Zeek.

Runs Suricata (and optionally Zeek) on the same 9-PCAP sandbox holdout
that v2 + python_only were evaluated on, parses the alert / event
output, and emits per-PCAP recall plus an aggregate.

Methodology (apples-to-apples is harder here than for our model):

- Ground truth: all 349 flows in the 9 holdout PCAPs are labelled `Bot`
  at ingest. The IDS doesn't have to predict the exact malware family;
  it just has to *flag the PCAP as malicious*.

- Per-PCAP recall: did the IDS produce >= 1 alert (any signature) on
  this PCAP? This is the lenient metric.
- Per-flow recall (Suricata only — Zeek doesn't ship signatures by
  default): for each flow Suricata reported, does it have an alert?
  Suricata's flow definitions don't match cicflowmeter's exactly, so
  this is approximate; we report both numbers and let the reader pick.

What this is NOT:
- A fair comparison of "alert rate" (signature counts include FP-prone
  rules in ET Open).
- A test of Suricata's intended deployment (live network with rule
  tuning); we run with default ET Open and unmodified suricata.yaml.

Usage:
    python scripts/external_benchmark.py
    python scripts/external_benchmark.py --tools suricata --skip-pull
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

OUT_DIR = ROOT / "results" / "external_benchmark"
SURICATA_RULES_DIR = OUT_DIR / "suricata_rules"
SPLIT_JSON = ROOT / "results" / "python_only" / "sandbox_split.json"
SANDBOX_DIR = ROOT / "data" / "sandbox_malware"
SURICATA_IMAGE = "jasonish/suricata:latest"
ZEEK_IMAGE = "zeek/zeek:latest"


def cygpath(p: Path) -> str:
    """Convert a /c/... or POSIX path to Windows form for Docker on Windows."""
    if os.name == "nt" or "MSYSTEM" in os.environ:
        try:
            r = subprocess.run(["cygpath", "-w", str(p)],
                                 capture_output=True, text=True, check=True)
            return r.stdout.strip()
        except (FileNotFoundError, subprocess.CalledProcessError):
            return str(p)
    return str(p)


def find_pcap(basename: str) -> Path:
    for d in ("stratosphere", "mta"):
        p = SANDBOX_DIR / d / basename
        if p.exists():
            return p
    raise FileNotFoundError(basename)


def docker_run_suricata(pcap_path: Path, out_dir: Path) -> Dict:
    """Run Suricata in Docker on one PCAP, return parsed event stats."""
    out_dir.mkdir(parents=True, exist_ok=True)
    win_rules = cygpath(SURICATA_RULES_DIR)
    win_pcap = cygpath(pcap_path)
    win_out = cygpath(out_dir)
    env = {**os.environ, "MSYS_NO_PATHCONV": "1"}
    t0 = time.time()
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{win_rules}:/var/lib/suricata/rules",
        "-v", f"{win_pcap}:/pcap.pcap:ro",
        "-v", f"{win_out}:/output",
        SURICATA_IMAGE,
        "-r", "/pcap.pcap", "-l", "/output",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    dt = time.time() - t0
    if proc.returncode != 0:
        return {"error": f"docker exit {proc.returncode}",
                "stderr": proc.stderr[-500:],
                "wall_time_s": round(dt, 1)}
    eve = out_dir / "eve.json"
    if not eve.exists():
        return {"error": "no eve.json produced",
                "wall_time_s": round(dt, 1)}
    counts: Dict[str, int] = {}
    alert_signatures: Dict[str, int] = {}
    flows_with_alert = set()
    flows_total = set()
    with eve.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            t = ev.get("event_type", "?")
            counts[t] = counts.get(t, 0) + 1
            fid = ev.get("flow_id")
            if t == "flow" and fid is not None:
                flows_total.add(fid)
            if t == "alert":
                if fid is not None:
                    flows_with_alert.add(fid)
                sig = ev.get("alert", {}).get("signature", "?")
                alert_signatures[sig] = alert_signatures.get(sig, 0) + 1
    return {
        "event_counts": counts,
        "n_alerts": counts.get("alert", 0),
        "n_flows_seen": len(flows_total),
        "n_flows_with_alert": len(flows_with_alert),
        "top_signatures": dict(
            sorted(alert_signatures.items(), key=lambda kv: -kv[1])[:5]),
        "wall_time_s": round(dt, 1),
    }


def docker_run_zeek(pcap_path: Path, out_dir: Path) -> Dict:
    """Run Zeek on one PCAP. Zeek doesn't have signatures by default —
    we report flows + notices + weird events."""
    out_dir.mkdir(parents=True, exist_ok=True)
    win_pcap = cygpath(pcap_path)
    win_out = cygpath(out_dir)
    env = {**os.environ, "MSYS_NO_PATHCONV": "1"}
    t0 = time.time()
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{win_pcap}:/pcap.pcap:ro",
        "-v", f"{win_out}:/output",
        "-w", "/output",
        ZEEK_IMAGE,
        "zeek", "-r", "/pcap.pcap", "LogAscii::use_json=T",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    dt = time.time() - t0
    if proc.returncode != 0:
        return {"error": f"docker exit {proc.returncode}",
                "stderr": proc.stderr[-500:],
                "wall_time_s": round(dt, 1)}
    n_conn = 0
    n_notice = 0
    n_weird = 0
    if (out_dir / "conn.log").exists():
        n_conn = sum(1 for _ in (out_dir / "conn.log").open(
            encoding="utf-8", errors="replace"))
    if (out_dir / "notice.log").exists():
        n_notice = sum(1 for _ in (out_dir / "notice.log").open(
            encoding="utf-8", errors="replace"))
    if (out_dir / "weird.log").exists():
        n_weird = sum(1 for _ in (out_dir / "weird.log").open(
            encoding="utf-8", errors="replace"))
    return {
        "n_conn_log_lines": n_conn,
        "n_notice_log_lines": n_notice,
        "n_weird_log_lines": n_weird,
        "wall_time_s": round(dt, 1),
    }


def update_suricata_rules() -> None:
    """Run suricata-update via Docker — fetches ET Open rules into
    SURICATA_RULES_DIR."""
    SURICATA_RULES_DIR.mkdir(parents=True, exist_ok=True)
    win_rules = cygpath(SURICATA_RULES_DIR)
    env = {**os.environ, "MSYS_NO_PATHCONV": "1"}
    print(f"  fetching ET Open rules to {SURICATA_RULES_DIR}...")
    proc = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "suricata-update",
          "-v", f"{win_rules}:/var/lib/suricata/rules",
          SURICATA_IMAGE],
        capture_output=True, text=True, env=env)
    rules_file = SURICATA_RULES_DIR / "suricata.rules"
    if not rules_file.exists():
        print("  ERROR: suricata-update failed to write rules file")
        if proc.stderr:
            print("  stderr tail:", proc.stderr[-300:])
        sys.exit(1)
    n_rules = sum(1 for line in rules_file.open(encoding="utf-8")
                    if line.strip() and not line.startswith("#"))
    print(f"  loaded ~{n_rules:,} rules")


def main(argv=None) -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    p = argparse.ArgumentParser()
    p.add_argument("--tools", default="suricata",
                    help="comma-separated subset of {suricata, zeek}")
    p.add_argument("--skip-pull", action="store_true",
                    help="don't docker-pull (use local cache)")
    p.add_argument("--skip-rule-update", action="store_true",
                    help="reuse existing suricata.rules from previous run")
    args = p.parse_args(argv)

    tools = [s.strip() for s in args.tools.split(",") if s.strip()]
    print(f"=== External benchmark vs {', '.join(tools)} ===\n")

    if "suricata" in tools and not args.skip_pull:
        print("[pull] Suricata image")
        subprocess.run(["docker", "pull", SURICATA_IMAGE],
                         capture_output=True)
    if "zeek" in tools and not args.skip_pull:
        print("[pull] Zeek image")
        subprocess.run(["docker", "pull", ZEEK_IMAGE], capture_output=True)

    if "suricata" in tools and not args.skip_rule_update:
        print("\n[rules] Updating Suricata ET Open ruleset")
        update_suricata_rules()

    print("\n[holdout] Loading 9-PCAP sandbox holdout list")
    split = json.loads(SPLIT_JSON.read_text(encoding="utf-8"))
    holdout = [meta["pcap"] for meta in split["holdout"]["pcaps"]]
    print(f"  {len(holdout)} PCAPs")

    results: Dict[str, Dict] = {"suricata": {}, "zeek": {}}
    for i, basename in enumerate(holdout, 1):
        pcap_path = find_pcap(basename)
        size_mb = pcap_path.stat().st_size / 1e6
        print(f"\n[{i}/{len(holdout)}] {basename}  ({size_mb:.1f} MB)")
        if "suricata" in tools:
            sub_out = OUT_DIR / "suricata" / basename
            r = docker_run_suricata(pcap_path, sub_out)
            results["suricata"][basename] = r
            if "error" in r:
                print(f"  suricata ERROR: {r['error']}")
            else:
                print(f"  suricata: {r['n_alerts']} alerts, "
                      f"{r['n_flows_with_alert']}/{r['n_flows_seen']} "
                      f"flows-with-alert  ({r['wall_time_s']}s)")
        if "zeek" in tools:
            sub_out = OUT_DIR / "zeek" / basename
            r = docker_run_zeek(pcap_path, sub_out)
            results["zeek"][basename] = r
            if "error" in r:
                print(f"  zeek ERROR: {r['error']}")
            else:
                print(f"  zeek: conn={r['n_conn_log_lines']} "
                      f"notice={r['n_notice_log_lines']} "
                      f"weird={r['n_weird_log_lines']}  "
                      f"({r['wall_time_s']}s)")

    # Aggregate
    print("\n[aggregate]")
    summary = {"per_tool": {}}
    for tool in tools:
        per_pcap = results.get(tool, {})
        n_pcaps = len(per_pcap)
        if tool == "suricata":
            n_pcaps_with_alert = sum(
                1 for r in per_pcap.values()
                if r.get("n_alerts", 0) > 0)
            total_alerts = sum(r.get("n_alerts", 0)
                                 for r in per_pcap.values())
            total_flows = sum(r.get("n_flows_seen", 0)
                                for r in per_pcap.values())
            total_alerted_flows = sum(r.get("n_flows_with_alert", 0)
                                          for r in per_pcap.values())
            summary["per_tool"][tool] = {
                "n_pcaps": n_pcaps,
                "n_pcaps_with_at_least_one_alert": n_pcaps_with_alert,
                "per_pcap_recall": (n_pcaps_with_alert / n_pcaps
                                       if n_pcaps else 0),
                "total_alerts": total_alerts,
                "total_flows_seen": total_flows,
                "total_flows_with_alert": total_alerted_flows,
                "per_flow_recall_approx": (total_alerted_flows / total_flows
                                              if total_flows else 0),
            }
            r = summary["per_tool"][tool]
            print(f"  Suricata:")
            print(f"    Per-PCAP recall (>=1 alert): "
                  f"{r['n_pcaps_with_at_least_one_alert']}/{r['n_pcaps']} "
                  f"= {r['per_pcap_recall']*100:.1f} %")
            print(f"    Per-flow recall (approx):    "
                  f"{r['total_flows_with_alert']}/{r['total_flows_seen']} "
                  f"= {r['per_flow_recall_approx']*100:.2f} %")
            print(f"    Total alerts across run:     {r['total_alerts']}")
        else:  # zeek — no signature engine by default
            total_conn = sum(r.get("n_conn_log_lines", 0)
                              for r in per_pcap.values())
            total_notice = sum(r.get("n_notice_log_lines", 0)
                                 for r in per_pcap.values())
            total_weird = sum(r.get("n_weird_log_lines", 0)
                                for r in per_pcap.values())
            summary["per_tool"][tool] = {
                "n_pcaps": n_pcaps,
                "total_conn_log_lines": total_conn,
                "total_notice_log_lines": total_notice,
                "total_weird_log_lines": total_weird,
                "note": "Zeek has no signature engine by default; "
                        "notice / weird counts are anomaly heuristics, "
                        "not malware verdicts.",
            }
            r = summary["per_tool"][tool]
            print(f"  Zeek:")
            print(f"    conn  : {total_conn} flows logged")
            print(f"    notice: {total_notice}")
            print(f"    weird : {total_weird}")

    out_json = OUT_DIR / "external_benchmark.json"
    out = {"per_pcap": results, "summary": summary,
            "holdout_pcaps": holdout}
    out_json.write_text(json.dumps(out, indent=2, default=str),
                          encoding="utf-8")
    print(f"\n  Saved: {out_json.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
