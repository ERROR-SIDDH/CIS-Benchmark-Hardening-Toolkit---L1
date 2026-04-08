#!/bin/bash
# harden/harden_ssh.sh
# CIS Level 1: SSH Server Hardening

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/utils/colors.sh"
source "$SCRIPT_DIR/utils/helpers.sh"

section "Hardening: SSH Server"

SSH_CONFIG="/etc/ssh/sshd_config"

if ! command -v sshd &>/dev/null; then
    log_warn "sshd not installed — skipping SSH hardening"
    exit 0
fi

backup_file "$SSH_CONFIG"

# ---- Apply CIS SSH settings -------------------------------------------------
declare -A ssh_settings=(
    ["Protocol"]="2"
    ["LogLevel"]="VERBOSE"
    ["X11Forwarding"]="no"
    ["MaxAuthTries"]="4"
    ["IgnoreRhosts"]="yes"
    ["HostbasedAuthentication"]="no"
    ["PermitRootLogin"]="no"
    ["PermitEmptyPasswords"]="no"
    ["PermitUserEnvironment"]="no"
    ["Ciphers"]="aes256-ctr,aes192-ctr,aes128-ctr"
    ["MACs"]="hmac-sha2-512,hmac-sha2-256"
    ["KexAlgorithms"]="diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,ecdh-sha2-nistp521"
    ["ClientAliveInterval"]="300"
    ["ClientAliveCountMax"]="0"
    ["LoginGraceTime"]="60"
    ["Banner"]="/etc/issue.net"
    ["UsePAM"]="yes"
    ["AllowAgentForwarding"]="no"
    ["AllowTcpForwarding"]="no"
    ["TCPKeepAlive"]="no"
    ["Compression"]="no"
    ["MaxSessions"]="4"
    ["PrintLastLog"]="yes"
)

for key in "${!ssh_settings[@]}"; do
    value="${ssh_settings[$key]}"
    if grep -qiE "^\s*#?\s*${key}\s" "$SSH_CONFIG"; then
        sed -i "s|^\s*#\?\s*${key}\s.*|${key} ${value}|I" "$SSH_CONFIG"
    else
        echo "${key} ${value}" >> "$SSH_CONFIG"
    fi
    log_apply "SSH: $key = $value"
done

# ---- Legal banner -----------------------------------------------------------
cat > /etc/issue.net << 'EOF'
*******************************************************************************
                          AUTHORIZED ACCESS ONLY

This system is for the use of authorized users only. All activity is monitored
and logged. Unauthorized access is strictly prohibited and will be prosecuted
to the full extent of the law.
*******************************************************************************
EOF
cat > /etc/issue << 'EOF'
Authorized users only. All activity is logged.
EOF
log_pass "Legal banners configured"

# ---- SSH host key permissions -----------------------------------------------
find /etc/ssh -name "ssh_host_*_key" -exec chmod 600 {} \;
find /etc/ssh -name "ssh_host_*_key.pub" -exec chmod 644 {} \;
log_pass "SSH host key permissions fixed"

# ---- Restrict SSH config file permissions -----------------------------------
chmod 600 /etc/ssh/sshd_config
chown root:root /etc/ssh/sshd_config
log_pass "sshd_config permissions set to 600"

# ---- Validate and restart SSH -----------------------------------------------
if sshd -t 2>/dev/null; then
    systemctl restart sshd && log_pass "SSHD restarted successfully" || log_warn "SSHD restart failed"
else
    log_fail "SSH config has syntax errors — NOT restarting (check $SSH_CONFIG)"
fi

echo -e "\n${GREEN}[SSH HARDENING COMPLETE]${NC}"
