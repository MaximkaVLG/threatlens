#!/bin/bash
# End-to-end smoke test. Confirms the lab can capture attacker → victim
# traffic and write a valid PCAP to the bind-mounted host directory.
#
# Run from inside lab-attacker:
#   docker exec lab-attacker bash /work/attacks/_smoke_test.sh
set -e

VICTIM="${VICTIM:-172.28.0.10}"
OUT_DIR="${OUT_DIR:-/work/pcaps}"
mkdir -p "$OUT_DIR"
STAMP=$(date +%Y%m%d_%H%M%S)
PCAP="$OUT_DIR/smoketest_${STAMP}.pcap"

echo "[smoke] Starting tcpdump on eth0 → $PCAP"
tcpdump -i eth0 -w "$PCAP" -U "host $VICTIM" >/tmp/tcpdump.log 2>&1 &
TPID=$!
sleep 1

echo "[smoke] ping $VICTIM (expect 3 echoes)"
ping -c 3 "$VICTIM" | tail -3

echo "[smoke] SYN scan of 50 common ports (expect 22/80/21 open)"
nmap -sS -p 21,22,80,443,3306,5432,1-20 "$VICTIM" | grep -E "^[0-9]+/tcp" | head -10

sleep 1
kill -INT "$TPID" 2>/dev/null || true
sleep 1

SIZE=$(stat -c%s "$PCAP" 2>/dev/null || echo 0)
echo "[smoke] PCAP: $PCAP  ($SIZE bytes)"

python3 - <<PY
from scapy.all import rdpcap, TCP
p = rdpcap("$PCAP")
syn = sum(1 for x in p if x.haslayer(TCP) and x[TCP].flags & 0x02)
print(f"[smoke] scapy verify: {len(p)} packets, {syn} SYN-flagged")
PY
