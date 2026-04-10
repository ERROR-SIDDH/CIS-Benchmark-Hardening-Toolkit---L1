#!/bin/bash
# harden/harden_firewall.sh
# CIS Level 1 + Server-grade UFW Firewall Hardening
# Enhanced with: rate-limiting, anti-spoofing, packet scan drops,
#               INVALID drops, ICMP rate-limit, optional strict outbound

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/utils/colors.sh"
source "$SCRIPT_DIR/utils/helpers.sh"

# =============================================================================
# CONFIGURATION
# Set STRICT_OUTBOUND=true to restrict outbound to an explicit allowlist.
# WARNING: This may break apt, DNS, NTP, or custom services if misconfigured.
#          Review the allowlist below before enabling on production.
# =============================================================================
STRICT_OUTBOUND=false

section "Hardening: UFW Firewall (Server-Grade)"

# ---- Install UFW ------------------------------------------------------------
if ! is_installed "ufw"; then
    log_apply "Installing UFW..."
    apt-get install -y ufw &>/dev/null
fi
log_pass "UFW is installed"

# ---- Disable iptables alternatives if present -------------------------------
if is_installed "nftables"; then
    systemctl stop nftables 2>/dev/null || true
    systemctl disable nftables 2>/dev/null || true
    log_apply "nftables disabled (using UFW/iptables)"
fi

# ---- Reset UFW to a clean slate ---------------------------------------------
log_apply "Resetting UFW rules to default..."
ufw --force reset &>/dev/null

# ---- Default policies -------------------------------------------------------
ufw default deny incoming
ufw default deny forward
if [[ "$STRICT_OUTBOUND" == "true" ]]; then
    ufw default deny outgoing
    log_pass "Default UFW policy: deny incoming, DENY outgoing (strict mode), deny forward"
else
    ufw default allow outgoing
    log_pass "Default UFW policy: deny incoming, allow outgoing, deny forward"
fi

# ---- Loopback ---------------------------------------------------------------
ufw allow in  on lo
ufw allow out on lo
ufw deny  in  from 127.0.0.0/8  comment 'Anti-spoof: block lo-sourced outside lo'
ufw deny  in  from ::1           comment 'Anti-spoof: IPv6 loopback outside lo'
log_pass "Loopback interface configured"

# ---- SSH: rate-limited (replaces bare allow) --------------------------------
# Drops connections from IPs making >6 new connections in 30 seconds
ufw limit in ssh comment 'CIS: SSH rate-limited brute-force protection'
log_pass "SSH (port 22) rate-limited (>6 conns/30s from same IP will be blocked)"

# ---- Strict outbound allowlist (opt-in) -------------------------------------
if [[ "$STRICT_OUTBOUND" == "true" ]]; then
    section "Strict Outbound Allowlist"
    log_apply "STRICT_OUTBOUND=true: applying outbound allowlist..."

    ufw allow out to any port 53  proto udp comment 'Allow: DNS (UDP)'
    ufw allow out to any port 53  proto tcp comment 'Allow: DNS (TCP)'
    ufw allow out to any port 80  proto tcp comment 'Allow: HTTP (apt, updates)'
    ufw allow out to any port 443 proto tcp comment 'Allow: HTTPS'
    ufw allow out to any port 123 proto udp comment 'Allow: NTP'
    ufw allow out to any port 465 proto tcp comment 'Allow: SMTP submission (SSL)'
    ufw allow out to any port 587 proto tcp comment 'Allow: SMTP submission (STARTTLS)'
    # SSH out (for git/remote access from server itself)
    ufw allow out to any port 22  proto tcp comment 'Allow: SSH outbound'

    log_pass "Strict outbound allowlist applied (DNS,HTTP,HTTPS,NTP,SMTP,SSH)"
    log_warn "All other outbound traffic will be dropped — review rules for your workload"
fi

# ---- UFW logging level upgrade ----------------------------------------------
ufw logging on
ufw logging high
log_pass "UFW logging enabled (level: high)"

# ---- Patch /etc/ufw/before.rules for low-level iptables hardening ----------
section "iptables before.rules Hardening"

BEFORE_RULES="/etc/ufw/before.rules"
backup_file "$BEFORE_RULES"

# We inject our rules into the *filter section, before the COMMIT line.
# Use a sentinel comment so we never double-apply on repeated runs.
SENTINEL="# CIS-SERVER-HARDENING-INJECTED"

if grep -q "$SENTINEL" "$BEFORE_RULES" 2>/dev/null; then
    log_warn "before.rules hardening already applied — skipping re-injection"
else
    log_apply "Injecting server-grade iptables rules into $BEFORE_RULES..."

    # Build the block to inject
    INJECT=$(cat <<'IPTBLOCK'
# CIS-SERVER-HARDENING-INJECTED
# =========================================================================
# Server-grade packet hardening — injected by harden_firewall.sh
# =========================================================================

# ---- Drop INVALID state packets (used in scans/hijacks) ------------------
-A ufw-before-input  -m conntrack --ctstate INVALID -j DROP
-A ufw-before-output -m conntrack --ctstate INVALID -j DROP

# ---- Drop NULL scans (all TCP flags off) ---------------------------------
-A ufw-before-input -p tcp --tcp-flags ALL NONE -j DROP

# ---- Drop XMAS scans (all TCP flags on) ----------------------------------
-A ufw-before-input -p tcp --tcp-flags ALL ALL -j DROP

# ---- Drop FIN scans (FIN only, no ACK, no SYN) --------------------------
-A ufw-before-input -p tcp --tcp-flags ALL FIN -j DROP

# ---- Drop new TCP connections that don't start with SYN ------------------
-A ufw-before-input -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

# ---- Anti-spoofing: drop RFC1918/bogon sources on any external iface -----
-A ufw-before-input -s 10.0.0.0/8     ! -i lo -j DROP
-A ufw-before-input -s 172.16.0.0/12  ! -i lo -j DROP
-A ufw-before-input -s 192.168.0.0/16 ! -i lo -j DROP
-A ufw-before-input -s 169.254.0.0/16 ! -i lo -j DROP
-A ufw-before-input -s 0.0.0.0/8      ! -i lo -j DROP
-A ufw-before-input -s 240.0.0.0/4    ! -i lo -j DROP
-A ufw-before-input -s 255.255.255.255 ! -i lo -j DROP

# ---- ICMP rate-limiting (allow ping, block floods) -----------------------
# Allow echo-request at max 1/second with burst of 5
-A ufw-before-input -p icmp --icmp-type echo-request \
    -m limit --limit 1/second --limit-burst 5 -j ACCEPT
# Drop excess echo-requests (flood protection)
-A ufw-before-input -p icmp --icmp-type echo-request -j DROP
# Drop all other ICMP types (timestamp, address-mask, redirect, etc.)
-A ufw-before-input -p icmp ! --icmp-type echo-request -j DROP

IPTBLOCK
)

    # Insert our block just before the COMMIT line in the *filter section
    # We find the last COMMIT line and insert before it
    python3 - "$BEFORE_RULES" "$INJECT" <<'PYEOF'
import sys

rules_file = sys.argv[1]
inject = sys.argv[2]

with open(rules_file, 'r') as f:
    lines = f.readlines()

# Find the last COMMIT line (end of *filter block)
commit_idx = None
for i, line in enumerate(lines):
    if line.strip() == 'COMMIT':
        commit_idx = i

if commit_idx is None:
    print("WARNING: Could not find COMMIT line in before.rules", file=sys.stderr)
    sys.exit(1)

# Insert our block before the last COMMIT
new_lines = lines[:commit_idx] + [inject + '\n'] + lines[commit_idx:]

with open(rules_file, 'w') as f:
    f.writelines(new_lines)

print("Injection successful")
PYEOF

    if [[ $? -eq 0 ]]; then
        log_pass "INVALID packet drop rules injected"
        log_pass "NULL / XMAS / FIN scan drop rules injected"
        log_pass "New-TCP-not-SYN drop rule injected"
        log_pass "Anti-spoofing (RFC1918/bogon) rules injected"
        log_pass "ICMP rate-limit (1/s, burst 5) injected"
    else
        log_fail "Failed to inject before.rules — check $BEFORE_RULES manually"
    fi
fi

# ---- Also harden /etc/ufw/before6.rules (IPv6) with INVALID drop ----------
BEFORE6_RULES="/etc/ufw/before6.rules"
if [[ -f "$BEFORE6_RULES" ]]; then
    backup_file "$BEFORE6_RULES"
    if ! grep -q "$SENTINEL" "$BEFORE6_RULES" 2>/dev/null; then
        python3 - "$BEFORE6_RULES" "# CIS-SERVER-HARDENING-INJECTED
-A ufw6-before-input -m conntrack --ctstate INVALID -j DROP
" <<'PYEOF'
import sys
rules_file = sys.argv[1]
inject = sys.argv[2]
with open(rules_file, 'r') as f:
    lines = f.readlines()
commit_idx = None
for i, line in enumerate(lines):
    if line.strip() == 'COMMIT':
        commit_idx = i
if commit_idx is None:
    sys.exit(1)
new_lines = lines[:commit_idx] + [inject + '\n'] + lines[commit_idx:]
with open(rules_file, 'w') as f:
    f.writelines(new_lines)
PYEOF
        log_pass "IPv6 before6.rules: INVALID packet drop injected"
    fi
fi

# ---- Ensure UFW's own sysctl.conf doesn't re-enable IP forwarding ----------
section "UFW sysctl Alignment"
UFW_SYSCTL="/etc/ufw/sysctl.conf"
backup_file "$UFW_SYSCTL"
set_config "net/ipv4/ip_forward"                     "0" "$UFW_SYSCTL" "="
set_config "net/ipv6/conf/default/forwarding"        "0" "$UFW_SYSCTL" "="
set_config "net/ipv6/conf/all/forwarding"            "0" "$UFW_SYSCTL" "="
set_config "net/ipv4/conf/all/accept_source_route"   "0" "$UFW_SYSCTL" "="
set_config "net/ipv4/conf/default/accept_source_route" "0" "$UFW_SYSCTL" "="
log_pass "UFW sysctl.conf aligned (no forwarding, no source-routing)"

# ---- IPv6 in UFW config -----------------------------------------------------
UFW_DEFAULT="/etc/default/ufw"
backup_file "$UFW_DEFAULT"
sed -i 's/^IPV6=.*/IPV6=no/' "$UFW_DEFAULT" 2>/dev/null || true
log_pass "IPv6 disabled in UFW config (/etc/default/ufw)"

# ---- Enable UFW -------------------------------------------------------------
ufw --force enable
systemctl enable ufw --now &>/dev/null
log_pass "UFW enabled and active"

# ---- Reload to apply before.rules changes -----------------------------------
log_apply "Reloading UFW to apply before.rules..."
ufw --force reload &>/dev/null && log_pass "UFW reloaded successfully" || log_warn "UFW reload failed — run: sudo ufw reload"

# ---- Restrict /etc/hosts.allow & hosts.deny ---------------------------------
section "TCP Wrappers (hosts.allow / hosts.deny)"

HOSTS_ALLOW="/etc/hosts.allow"
HOSTS_DENY="/etc/hosts.deny"

backup_file "$HOSTS_ALLOW"
backup_file "$HOSTS_DENY"

cat > "$HOSTS_DENY" <<'EOF'
# CIS Benchmark: Deny all by default
ALL: ALL
EOF

cat > "$HOSTS_ALLOW" <<'EOF'
# CIS Benchmark: Allow specific services here
# Example: sshd: 192.168.1.0/24
# Add allowed hosts/networks above this line
sshd: ALL
EOF

chmod 644 "$HOSTS_ALLOW" "$HOSTS_DENY"
log_pass "TCP wrappers configured (deny all, allow SSH)"

# ---- Show final status ------------------------------------------------------
echo ""
echo -e "${CYAN}--- Final UFW Status ---${NC}"
ufw status verbose

echo -e "\n${GREEN}[FIREWALL HARDENING COMPLETE]${NC}"
echo -e "${YELLOW}[NOTE]${NC} Review STRICT_OUTBOUND=false at top of this script to optionally"
echo -e "       restrict outbound traffic to an explicit allowlist."
