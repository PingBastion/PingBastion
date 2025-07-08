#!/usr/bin/env bash
# diag_firewall.sh — Auto-diagnose connectivity / forwarding issues
#
# Example:
#   ssh root@<firewall-ip> 'bash -s' < diag_firewall.sh \
#     | tee firewall_diag_$(date +%F_%H%M%S).log
#
# Notes
# -----
# * The script never aborts on a single failed check; it always runs to the end.
# * Colour-coded [OK] / [FAIL] messages make problems easy to spot.
# * Capture the whole run locally with `tee`, since everything is written to stdout.

set -Euo pipefail        # no “-e” → one failure won’t stop the rest of the checks
exec 2>&1                # merge stderr into stdout

banner() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
fail()   { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*"; }
pass()   { printf '\033[1;32m[OK  ]\033[0m %s\n'  "$*"; }

require_root() { [[ $EUID -eq 0 ]] || { echo "Must run as root"; exit 2; }; }

detect_ifaces() {
  # WAN ➜ interface that owns the default IPv4 route
  WAN_IF=$(ip -4 route | awk '/^default/ {print $5; exit}')

  # LAN ➜ first *non-WAN* interface with an RFC1918 IPv4
  LAN_IF=$(
    ip -4 -o addr show scope global \
    | awk '$4 ~ /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/ {print $2}' \
    | grep -v "^${WAN_IF}$" | head -n1
  )
}

check_link() {
  banner "Interface link status"
  for DEV in "$WAN_IF" "$LAN_IF"; do
    [[ -n $DEV ]] || continue
    STATE=$(cat /sys/class/net/$DEV/operstate 2>/dev/null || echo unknown)
    case "$STATE" in
      up)       pass "$DEV link is up" ;;
      unknown)  pass "$DEV link state unknown (USB-tethering / virtual)" ;;
      *)        fail "$DEV link is $STATE" ;;
    esac
  done
}

check_addr() {
  banner "IP addressing"

  local devs=()
  [[ -n $WAN_IF ]] && devs+=("$WAN_IF")
  [[ -n $LAN_IF ]] && devs+=("$LAN_IF")

  if ((${#devs[@]})); then
    ip -br addr show "${devs[@]}" || true   # never abort on ip(8) error
  else
    fail "No network interfaces detected!"
    return
  fi

  if [[ -n $WAN_IF ]]; then
    [[ -n $(ip -4 addr show "$WAN_IF" | awk '/inet /') ]] \
      && pass "$WAN_IF has IPv4" \
      || fail "$WAN_IF has no IPv4 address"
  else
    fail "No WAN interface detected (no default route yet)"
  fi

  if [[ -n $LAN_IF ]]; then
    [[ -n $(ip -4 addr show "$LAN_IF" | awk '/inet /') ]] \
      && pass "$LAN_IF has IPv4" \
      || fail "$LAN_IF has no IPv4 address"
  fi
}

check_routes() {
  banner "Routing table"
  ip route show || true
  ip route get 8.8.8.8 &>/dev/null \
    && pass "Default route present" \
    || fail "No default route!"
}

check_dns() {
  banner "DNS resolution test"
  if command -v dig &>/dev/null; then
    dig +short google.com | head -n1 | grep -qE '^[0-9.]+' \
      && pass "DNS resolves" \
      || fail "DNS failed"
  else
    getent hosts google.com | grep -qE '^[0-9.]+' \
      && pass "DNS resolves (getent)" \
      || fail "DNS failed"
  fi
}

ping_tests() {
  banner "Connectivity tests"

  if [[ -n $WAN_IF ]]; then
    ping -c2 -I "$WAN_IF" -W1 8.8.8.8 \
      && pass "Ping 8.8.8.8 via $WAN_IF" \
      || fail "Ping 8.8.8.8 via $WAN_IF failed"
  else
    ping -c2 -W1 8.8.8.8 \
      && pass "Ping 8.8.8.8 (no iface specified)" \
      || fail "Ping 8.8.8.8 failed"
  fi

  ping -c2 -W1 1.1.1.1 &>/dev/null \
    && pass "Ping 1.1.1.1 (any iface)" \
    || fail "Ping 1.1.1.1 failed"
}

check_forwarding() {
  banner "Kernel IP forwarding"
  [[ $(sysctl -n net.ipv4.ip_forward) -eq 1 ]] \
    && pass "IPv4 forwarding enabled" \
    || fail "net.ipv4.ip_forward is 0"
}

check_nat() {
  banner "NAT / masquerade rule"
  if command -v nft &>/dev/null; then
    nft list ruleset | grep -q masquerade \
      && pass "nftables masquerade present" \
      || fail "No masquerade in nftables"
  elif command -v iptables &>/dev/null; then
    iptables -t nat -S | grep -q MASQUERADE \
      && pass "iptables MASQUERADE present" \
      || fail "No MASQUERADE rule"
  else
    fail "Neither nft nor iptables found"
  fi
}

check_firewall_rules() {
  banner "Firewall ruleset snapshot"
  if command -v nft &>/dev/null; then
    nft list ruleset || true
  else
    iptables -L -v -n || true
  fi
}

check_conntrack() {
  banner "Conntrack statistics"
  command -v conntrack &>/dev/null && \
    conntrack -L | wc -l | xargs printf "Active connections: %s\n"
}

check_logs() {
  banner "Recent dmesg / syslog (netfilter & netplan)"
  dmesg --ctime | grep -E 'nft|iptables|netplan' | tail -n20 || true
  journalctl -u systemd-networkd -u netplan-apply --no-pager -n 20 || true
}

summary() {
  banner "Diagnostics complete"
  echo "Diagnostics written to stdout – use tee to capture a local file."
}

main() {
  require_root
  detect_ifaces
  banner "Detected WAN interface: ${WAN_IF:-<none>} | LAN interface: ${LAN_IF:-<none>}"
  check_link
  check_addr
  check_routes
  check_dns
  ping_tests
  check_forwarding
  check_nat
  check_firewall_rules
  check_conntrack
  check_logs
  summary
}

main "$@"
