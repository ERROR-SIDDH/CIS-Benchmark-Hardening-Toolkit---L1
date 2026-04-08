#!/bin/bash
# harden/harden_filesystem.sh
# CIS Level 1: File System & Permission Hardening

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/utils/colors.sh"
source "$SCRIPT_DIR/utils/helpers.sh"

section "Hardening: File System Permissions"

# ---- Critical system file permissions ---------------------------------------
declare -A file_perms=(
    ["/etc/passwd"]="644 root root"
    ["/etc/passwd-"]="600 root root"
    ["/etc/shadow"]="640 root shadow"
    ["/etc/shadow-"]="600 root shadow"
    ["/etc/group"]="644 root root"
    ["/etc/group-"]="600 root root"
    ["/etc/gshadow"]="640 root shadow"
    ["/etc/gshadow-"]="600 root shadow"
    ["/etc/crontab"]="600 root root"
    ["/etc/ssh/sshd_config"]="600 root root"
    ["/etc/sudoers"]="440 root root"
    ["/boot/grub/grub.cfg"]="600 root root"
)

for file in "${!file_perms[@]}"; do
    if [[ -f "$file" ]]; then
        read -r perm owner group <<< "${file_perms[$file]}"
        chmod "$perm" "$file"
        chown "$owner:$group" "$file"
        log_pass "Permissions set: $file ($perm, $owner:$group)"
    else
        log_warn "File not found: $file (skipping)"
    fi
done

# ---- Cron directory permissions ---------------------------------------------
for crondir in /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.hourly /etc/cron.d; do
    if [[ -d "$crondir" ]]; then
        chmod 700 "$crondir"
        chown root:root "$crondir"
        log_pass "Cron dir secured: $crondir"
    fi
done

# Restrict cron/at to authorized users
rm -f /etc/cron.deny /etc/at.deny
touch /etc/cron.allow /etc/at.allow
chmod 600 /etc/cron.allow /etc/at.allow
chown root:root /etc/cron.allow /etc/at.allow
log_pass "cron.allow and at.allow restricted to root"

# ---- SUID/SGID audit --------------------------------------------------------
section "SUID/SGID File Audit"

SUID_REPORT="/var/log/cis-suid-report.txt"
log_apply "Scanning for SUID/SGID files (this may take a moment)..."
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort > "$SUID_REPORT"
SUID_COUNT=$(wc -l < "$SUID_REPORT")
log_warn "Found $SUID_COUNT SUID/SGID files. Saved to $SUID_REPORT — review manually."

# ---- World-writable files audit ---------------------------------------------
WW_REPORT="/var/log/cis-world-writable.txt"
log_apply "Scanning for world-writable files..."
find / -xdev -type f -perm -0002 2>/dev/null | grep -v proc > "$WW_REPORT" || true
WW_COUNT=$(wc -l < "$WW_REPORT")
if [[ "$WW_COUNT" -eq 0 ]]; then
    log_pass "No world-writable files found"
else
    log_warn "$WW_COUNT world-writable file(s) found. Saved to $WW_REPORT"
fi

# ---- Unowned files audit ----------------------------------------------------
log_apply "Scanning for unowned files..."
UNOWNED=$(find / -xdev \( -nouser -o -nogroup \) 2>/dev/null | grep -v proc || true)
if [[ -z "$UNOWNED" ]]; then
    log_pass "No unowned files found"
else
    echo "$UNOWNED" > /var/log/cis-unowned-files.txt
    log_warn "Unowned files found — saved to /var/log/cis-unowned-files.txt"
fi

# ---- Sticky bit on world-writable directories --------------------------------
section "World-Writable Directory Sticky Bit"

find / -xdev -type d -perm -0002 2>/dev/null | while read -r dir; do
    if [[ ! $(stat -c "%a" "$dir") == *"1"* ]]; then
        chmod +t "$dir" 2>/dev/null && log_apply "Sticky bit set on: $dir"
    fi
done
log_pass "Sticky bit check complete on world-writable directories"

# ---- /tmp hardening ---------------------------------------------------------
section "/tmp Hardening"

SYSTEMD_TMP="/etc/systemd/system/tmp.mount"
if ! grep -q " on /tmp " /proc/mounts 2>/dev/null; then
    # Bind-mount /tmp with restrictions if not already on separate partition
    if [[ ! -f "$SYSTEMD_TMP" ]]; then
        cat > "$SYSTEMD_TMP" << 'EOF'
[Unit]
Description=Temporary Directory /tmp
ConditionPathIsSymbolicLink=!/tmp

[Mount]
What=tmpfs
Where=/tmp
Type=tmpfs
Options=mode=1777,strictatime,noexec,nodev,nosuid,size=2G

[Install]
WantedBy=local-fs.target
EOF
        systemctl daemon-reload
        systemctl enable tmp.mount --now &>/dev/null && log_pass "/tmp mounted as tmpfs with noexec,nodev,nosuid" || log_warn "/tmp tmpfs mount failed"
    fi
else
    log_pass "/tmp is already on a separate mount"
fi

# ---- /var/tmp -> /tmp symlink -----------------------------------------------
if [[ ! -L /var/tmp ]]; then
    if [[ -d /var/tmp ]]; then
        rm -rf /var/tmp
    fi
    ln -s /tmp /var/tmp
    log_pass "/var/tmp linked to /tmp"
fi

# ---- Remove legacy .rhosts and .netrc files ---------------------------------
section "Legacy File Cleanup"
find /home /root -name ".rhosts" -o -name ".netrc" 2>/dev/null | while read -r f; do
    rm -f "$f" && log_apply "Removed: $f"
done
log_pass "Legacy .rhosts/.netrc cleanup done"

# ---- /etc/hosts.equiv -------------------------------------------------------
if [[ -f /etc/hosts.equiv ]]; then
    rm -f /etc/hosts.equiv
    log_pass "Removed /etc/hosts.equiv"
fi

echo -e "\n${GREEN}[FILESYSTEM HARDENING COMPLETE]${NC}"
