#!/bin/sh
# Apply realistic network impairments to the attacker's egress interface.
# Usage:  netem high-latency | netem lossy | netem low-bandwidth | netem clear
set -e
IFACE="${IFACE:-eth0}"
case "$1" in
  high-latency) tc qdisc replace dev "$IFACE" root netem delay 200ms 50ms distribution normal ;;
  lossy)        tc qdisc replace dev "$IFACE" root netem loss 3% delay 50ms 10ms ;;
  low-bw)       tc qdisc replace dev "$IFACE" root tbf rate 10mbit burst 32kbit latency 400ms ;;
  clear)        tc qdisc del dev "$IFACE" root 2>/dev/null || true ;;
  *)            echo "usage: netem {high-latency|lossy|low-bw|clear}" >&2; exit 1 ;;
esac
