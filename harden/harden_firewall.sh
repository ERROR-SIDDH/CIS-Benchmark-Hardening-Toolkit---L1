#!/bin/bash
# harden/harden_firewall.sh
# CIS Level 1: UFW Firewall Hardening

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/utils/colors.sh"
source "$SCRIPT_DIR/utils/helpers.sh"

section "Hardening: UFW Firewall"

# ---- Install UFW ------------------------------------------------------------
if ! is_installed "ufw"; then
    log_apply "Installing UFW..."
    apt-get install -y ufw &>/dev/null
fi

# ---- Disable iptables alternatives if present -------------------------------
if is_installed "nftables"; then
    systemctl stop nftables 2>/dev/null || true
    systemctl disable nftables 2>/dev/null || true
    log_apply "nftables disabled (using UFW)"
fi

# ---- Reset UFW to defaults --------------------------------------------------
log_apply "Resetting UFW rules to default..."
ufw --force reset &>/dev/null

# ---- Default policies -------------------------------------------------------
ufw default deny incoming
ufw default allow outgoing
ufw default deny forward
log_pass "Default UFW policy: deny incoming, allow outgoing, deny forward"

# ---- Allow SSH (essential - prevents lockout) -------------------------------
ufw allow ssh comment 'CIS: Allow SSH'
log_pass "SSH (port 22) allowed"

# ---- Loopback ---------------------------------------------------------------
ufw allow in on lo
ufw deny in from 127.0.0.0/8
ufw deny in from ::1
log_pass "Loopback interface configured"

# ---- Enable UFW logging -----------------------------------------------------
ufw logging on
ufw logging medium
log_pass "UFW logging enabled (medium)"

# ---- Enable UFW -------------------------------------------------------------
ufw --force enable
systemctl enable ufw --now &>/dev/null
log_pass "UFW enabled and active"

# ---- Show current rules -----------------------------------------------------
echo ""
echo -e "${CYAN}--- Current UFW Status ---${NC}"
ufw status verbose

# ---- IPv6 in UFW ------------------------------------------------------------
UFW_DEFAULT="/etc/default/ufw"
backup_file "$UFW_DEFAULT"
sed -i 's/^IPV6=.*/IPV6=no/' "$UFW_DEFAULT" 2>/dev/null || true
log_pass "IPv6 disabled in UFW config"

# ---- Restrict /etc/hosts.allow & hosts.deny ---------------------------------
section "TCP Wrappers (hosts.allow / hosts.deny)"

HOSTS_ALLOW="/etc/hosts.allow"
HOSTS_DENY="/etc/hosts.deny"

backup_file "$HOSTS_ALLOW"
backup_file "$HOSTS_DENY"

cat > "$HOSTS_DENY" << 'EOF'
# CIS Benchmark: Deny all by default
ALL: ALL
EOF

cat > "$HOSTS_ALLOW" << 'EOF'
# CIS Benchmark: Allow specific services here
# Example: sshd: 192.168.1.0/24
# Add allowed hosts/networks above this line
sshd: ALL
EOF

chmod 644 "$HOSTS_ALLOW" "$HOSTS_DENY"
log_pass "TCP wrappers configured (deny all, allow SSH)"

echo -e "\n${GREEN}[FIREWALL HARDENING COMPLETE]${NC}"
