#!/bin/bash
# harden/harden_services.sh
# CIS Level 1: Disable Unnecessary Services & Software

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/utils/colors.sh"
source "$SCRIPT_DIR/utils/helpers.sh"

section "Hardening: Unnecessary Services"

# ---- Services to disable/remove ---------------------------------------------
UNWANTED_PKGS=(
    "telnet"
    "telnetd"
    "rsh-client"
    "rsh-server"
    "talk"
    "talkd"
    "xinetd"
    "nis"
    "yp-tools"
    "tftp"
    "atftpd"
    "vsftpd"
    "ftp"
    "lpd"
    "cups"
    "isc-dhcp-server"
    "slapd"
    "nfs-kernel-server"
    "bind9"
    "dovecot-imapd"
    "dovecot-pop3d"
    "sendmail"
    "postfix"
    "squid"
    "snmpd"
)

for pkg in "${UNWANTED_PKGS[@]}"; do
    if is_installed "$pkg"; then
        log_apply "Removing $pkg..."
        apt-get remove --purge -y "$pkg" &>/dev/null && log_pass "Removed: $pkg" || log_warn "Could not remove: $pkg"
    else
        log_pass "Not installed: $pkg"
    fi
done

# ---- Disable unnecessary systemd services -----------------------------------
UNWANTED_SVCS=(
    "avahi-daemon"
    "cups"
    "isc-dhcp-server"
    "isc-dhcp-server6"
    "slapd"
    "nfs-server"
    "rpcbind"
    "bind9"
    "vsftpd"
    "apache2"
    "nginx"
    "squid"
    "smbd"
    "nmbd"
    "rsync"
    "snmpd"
)

for svc in "${UNWANTED_SVCS[@]}"; do
    if systemctl is-enabled "$svc" &>/dev/null; then
        systemctl stop "$svc" 2>/dev/null || true
        systemctl disable "$svc" 2>/dev/null
        log_pass "Disabled service: $svc"
    else
        log_pass "Service not enabled: $svc"
    fi
done

# ---- Configure postfix (local only) if installed ----------------------------
section "Postfix (Mail)"
if is_installed "postfix"; then
    backup_file "/etc/postfix/main.cf"
    set_config "inet_interfaces" "loopback-only" "/etc/postfix/main.cf" " = "
    systemctl restart postfix &>/dev/null && log_pass "Postfix restricted to localhost only"
fi

# ---- NFS security -----------------------------------------------------------
section "NFS"
if is_installed "nfs-common"; then
    backup_file "/etc/exports"
    # Ensure /etc/exports is empty or restrictive
    if [[ -f /etc/exports ]] && grep -qv "^#" /etc/exports 2>/dev/null; then
        log_warn "/etc/exports has active exports — review manually: /etc/exports"
    else
        log_pass "/etc/exports is empty or fully commented"
    fi
fi

# ---- X Window System --------------------------------------------------------
section "X Window System"
if is_installed "xserver-xorg" || is_installed "x11-common"; then
    log_warn "X Window System is installed — consider removing if this is a server"
else
    log_pass "X Window System not installed"
fi

# ---- Ensure CUPS not running ------------------------------------------------
section "Printing Services (CUPS)"
if systemctl is-active --quiet cups 2>/dev/null; then
    systemctl stop cups
    systemctl disable cups
    log_pass "CUPS stopped and disabled"
else
    log_pass "CUPS is not running"
fi

# ---- Ensure rpcbind is disabled ---------------------------------------------
if systemctl is-enabled rpcbind &>/dev/null; then
    systemctl stop rpcbind
    systemctl disable rpcbind
    log_pass "rpcbind disabled"
else
    log_pass "rpcbind not enabled"
fi

# ---- Ensure AppArmor is enabled ---------------------------------------------
section "AppArmor"
if is_installed "apparmor"; then
    systemctl enable apparmor --now &>/dev/null
    aa-status &>/dev/null && log_pass "AppArmor is active" || log_warn "AppArmor may not be fully enforcing"
    # Set all profiles to enforce mode
    if command -v aa-enforce &>/dev/null; then
        find /etc/apparmor.d -maxdepth 1 -type f | while read -r profile; do
            aa-enforce "$profile" &>/dev/null && log_apply "AppArmor enforcing: $profile"
        done
    fi
else
    log_apply "Installing AppArmor..."
    apt-get install -y apparmor apparmor-utils &>/dev/null
    systemctl enable apparmor --now &>/dev/null
    log_pass "AppArmor installed and enabled"
fi

# ---- GRUB password protection -----------------------------------------------
section "GRUB Bootloader"
if [[ ! -f /etc/grub.d/40_custom ]] || ! grep -q "password_pbkdf2" /etc/grub.d/40_custom 2>/dev/null; then
    log_warn "GRUB bootloader password NOT set — set manually with: grub-mkpasswd-pbkdf2"
    log_warn "Then add to /etc/grub.d/40_custom and run: update-grub"
else
    log_pass "GRUB password is configured"
fi

# ---- Ensure sudo is configured properly ------------------------------------
section "Sudo Configuration"
if ! is_installed "sudo"; then
    apt-get install -y sudo &>/dev/null
fi

SUDOERS="/etc/sudoers"
backup_file "$SUDOERS"

# Ensure sudo logs to syslog
if ! grep -q "Defaults.*logfile" "$SUDOERS" 2>/dev/null; then
    echo 'Defaults logfile="/var/log/sudo.log"' >> "$SUDOERS"
fi
if ! grep -q "Defaults.*log_input\|Defaults.*log_output" "$SUDOERS" 2>/dev/null; then
    echo 'Defaults log_input, log_output' >> "$SUDOERS"
fi
if ! grep -q "Defaults.*use_pty" "$SUDOERS" 2>/dev/null; then
    echo 'Defaults use_pty' >> "$SUDOERS"
fi

# Validate sudoers
visudo -c &>/dev/null && log_pass "sudoers configuration valid" || log_warn "sudoers has syntax issues — verify with: visudo -c"

echo -e "\n${GREEN}[SERVICE HARDENING COMPLETE]${NC}"
