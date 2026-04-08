#!/bin/bash
# harden/harden_logging.sh
# CIS Level 1: Logging, Auditing & journald Hardening

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/utils/colors.sh"
source "$SCRIPT_DIR/utils/helpers.sh"

section "Hardening: Logging & Auditing"

# ---- Install rsyslog --------------------------------------------------------
if ! is_installed "rsyslog"; then
    log_apply "Installing rsyslog..."
    apt-get install -y rsyslog &>/dev/null
fi
systemctl enable rsyslog --now &>/dev/null
log_pass "rsyslog enabled and started"

# ---- Configure rsyslog ------------------------------------------------------
RSYSLOG_CONF="/etc/rsyslog.conf"
backup_file "$RSYSLOG_CONF"

# Ensure proper log file permissions via FileCreateMode
append_if_missing '$FileCreateMode 0640' "$RSYSLOG_CONF"
append_if_missing '$umask 0022' "$RSYSLOG_CONF"

# Drop additional CIS logging rules
cat > /etc/rsyslog.d/50-cis.conf << 'EOF'
# CIS Benchmark: Ensure all auth events are logged
auth,authpriv.*                 /var/log/auth.log
*.*;auth,authpriv.none          -/var/log/syslog
kern.*                          -/var/log/kern.log
mail.*                          -/var/log/mail.log
cron.*                          /var/log/cron.log
daemon.*                        -/var/log/daemon.log
local0,local1.*                 -/var/log/localmessages
local2,local3.*                 -/var/log/localmessages
local4,local5.*                 -/var/log/localmessages
local6,local7.*                 -/var/log/localmessages

# Emergency messages to all users
*.emerg                         :omusrmsg:*
EOF
log_pass "rsyslog CIS rules applied"

systemctl restart rsyslog &>/dev/null && log_pass "rsyslog restarted" || log_warn "rsyslog restart failed"

# ---- Install & configure auditd ---------------------------------------------
if ! is_installed "auditd"; then
    log_apply "Installing auditd..."
    apt-get install -y auditd audispd-plugins &>/dev/null
fi
systemctl enable auditd --now &>/dev/null
log_pass "auditd enabled and started"

# ---- Audit rules ------------------------------------------------------------
AUDIT_RULES="/etc/audit/rules.d/cis.rules"
backup_file "$AUDIT_RULES"

cat > "$AUDIT_RULES" << 'EOF'
# =============================================================================
# CIS Benchmark Level 1 - Audit Rules
# Ubuntu 22.04 LTS
# =============================================================================

# --- Filesystem changes ------------------------------------------------------
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd

# --- Authentication & authorization ------------------------------------------
-w /var/log/auth.log -p wa -k auth
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /etc/pam.d/ -p wa -k pam

# --- System administration --------------------------------------------------
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/at.allow -p wa -k at
-w /etc/at.deny -p wa -k at

# --- Network config changes --------------------------------------------------
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/sysctl.d/ -p wa -k sysctl
-w /etc/hosts -p wa -k network
-w /etc/network/ -p wa -k network

# --- Module loading -----------------------------------------------------------
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# --- Privilege escalation ----------------------------------------------------
-a always,exit -F arch=b64 -S setuid -S setgid -k privilege_escalation
-a always,exit -F arch=b32 -S setuid -S setgid -k privilege_escalation

# --- Time changes ------------------------------------------------------------
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# --- User/group management ---------------------------------------------------
-a always,exit -F arch=b64 -S useradd -S usermod -S userdel -S groupadd -k user-mgmt

# --- File deletion -----------------------------------------------------------
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k delete

# --- Unsuccessful access attempts -------------------------------------------
-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S open -F exit=-EPERM  -F auid>=1000 -F auid!=4294967295 -k access

# --- Sudo usage --------------------------------------------------------------
-w /usr/bin/sudo -p x -k sudo
-w /usr/bin/su -p x -k su

# --- Make config immutable (last rule) ---------------------------------------
-e 2
EOF

log_apply "Loading audit rules..."
augenrules --load &>/dev/null && log_pass "Audit rules loaded" || log_warn "augenrules failed — manually run: augenrules --load"

# ---- auditd.conf settings ---------------------------------------------------
AUDITD_CONF="/etc/audit/auditd.conf"
backup_file "$AUDITD_CONF"
set_config "max_log_file" "8" "$AUDITD_CONF" " = "
set_config "max_log_file_action" "keep_logs" "$AUDITD_CONF" " = "
set_config "space_left_action" "email" "$AUDITD_CONF" " = "
set_config "action_mail_acct" "root" "$AUDITD_CONF" " = "
set_config "admin_space_left_action" "halt" "$AUDITD_CONF" " = "
log_pass "auditd.conf configured"

# ---- journald configuration -------------------------------------------------
JOURNALD_CONF="/etc/systemd/journald.conf"
backup_file "$JOURNALD_CONF"
set_config "Storage" "persistent" "$JOURNALD_CONF" "="
set_config "Compress" "yes" "$JOURNALD_CONF" "="
set_config "ForwardToSyslog" "yes" "$JOURNALD_CONF" "="
set_config "MaxFileSec" "1month" "$JOURNALD_CONF" "="
set_config "MaxRetentionSec" "1year" "$JOURNALD_CONF" "="
log_pass "journald configured for persistent storage"
systemctl restart systemd-journald &>/dev/null

# ---- Log file permissions ---------------------------------------------------
section "Log File Permissions"

for logfile in /var/log/syslog /var/log/auth.log /var/log/kern.log /var/log/cron.log; do
    if [[ -f "$logfile" ]]; then
        chmod 640 "$logfile"
        chown root:adm "$logfile" 2>/dev/null || chown root:root "$logfile"
        log_pass "Permissions set: $logfile"
    fi
done

# ---- logrotate --------------------------------------------------------------
cat > /etc/logrotate.d/cis-hardening << 'EOF'
/var/log/auth.log
/var/log/syslog
/var/log/kern.log
/var/log/cron.log
{
    rotate 12
    monthly
    compress
    missingok
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        invoke-rc.d rsyslog rotate > /dev/null
    endscript
}
EOF
log_pass "logrotate configured for CIS log files"

echo -e "\n${GREEN}[LOGGING HARDENING COMPLETE]${NC}"
