#!/bin/bash
# audit/baseline_audit.sh
# Scans the system BEFORE hardening and reports current compliance state.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/utils/colors.sh"
source "$SCRIPT_DIR/utils/helpers.sh"

REPORT_DIR="$SCRIPT_DIR/reports"
BASELINE_REPORT="$REPORT_DIR/baseline_report_$(date +%Y%m%d_%H%M%S).txt"
mkdir -p "$REPORT_DIR"
init_report

{
echo "============================================================"
echo " CIS Benchmark Level 1 - Baseline Audit"
echo " Host    : $(hostname)"
echo " OS      : $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')"
echo " Date    : $(date)"
echo " Kernel  : $(uname -r)"
echo "============================================================"
echo ""

# ---- 1. Filesystem Configuration -------------------------------------------
section "1. Filesystem Configuration"

for fs in cramfs freevxfs jffs2 hfs hfsplus squashfs udf; do
    if lsmod | grep -q "^$fs " 2>/dev/null || modprobe -n -v "$fs" 2>/dev/null | grep -q "insmod"; then
        log_fail "CIS 1.1.x: Filesystem module $fs is LOADED/LOADABLE"
        add_result "1.1.x" "Module $fs disabled" "FAIL" "$fs is loadable"
    else
        log_pass "CIS 1.1.x: Filesystem module $fs is disabled"
        add_result "1.1.x" "Module $fs disabled" "PASS"
    fi
done

# Check /tmp is a separate partition
if mount | grep -q " on /tmp "; then
    log_pass "CIS 1.1.2: /tmp is a separate partition"
    add_result "1.1.2" "/tmp separate partition" "PASS"
else
    log_fail "CIS 1.1.2: /tmp is NOT a separate partition"
    add_result "1.1.2" "/tmp separate partition" "FAIL"
fi

# Check nodev/nosuid/noexec on /tmp
for opt in nodev nosuid noexec; do
    if mount | grep " on /tmp " | grep -q "$opt"; then
        log_pass "CIS 1.1.3: /tmp mounted with $opt"
    else
        log_fail "CIS 1.1.3: /tmp NOT mounted with $opt"
    fi
done

# ---- 2. Software Updates ----------------------------------------------------
section "2. Software & Patch Management"

UPDATES=$(apt-get -s upgrade 2>/dev/null | grep -c "^Inst" || echo 0)
if [[ "$UPDATES" -eq 0 ]]; then
    log_pass "CIS 1.9: System is up to date"
    add_result "1.9" "System up to date" "PASS"
else
    log_fail "CIS 1.9: $UPDATES package update(s) pending"
    add_result "1.9" "System up to date" "FAIL" "$UPDATES updates pending"
fi

# ---- 3. SSH Configuration ---------------------------------------------------
section "3. SSH Server Configuration"

SSH_CONFIG="/etc/ssh/sshd_config"
if [[ -f "$SSH_CONFIG" ]]; then
    checks=(
        "PermitRootLogin:no"
        "PasswordAuthentication:no"
        "X11Forwarding:no"
        "MaxAuthTries:4"
        "IgnoreRhosts:yes"
        "HostbasedAuthentication:no"
        "PermitEmptyPasswords:no"
        "ClientAliveInterval:300"
        "ClientAliveCountMax:0"
        "Protocol:2"
    )
    for check in "${checks[@]}"; do
        key="${check%%:*}"
        expected="${check##*:}"
        actual=$(grep -iE "^\s*${key}" "$SSH_CONFIG" | awk '{print tolower($2)}' | head -1)
        if [[ "$actual" == "$expected" ]]; then
            log_pass "CIS 5.2.x: SSH $key = $actual"
            add_result "5.2.x" "SSH $key" "PASS"
        else
            log_fail "CIS 5.2.x: SSH $key = '${actual:-not set}' (expected: $expected)"
            add_result "5.2.x" "SSH $key" "FAIL" "got '${actual:-not set}', want '$expected'"
        fi
    done
else
    log_warn "sshd_config not found — SSH may not be installed"
fi

# ---- 4. Authentication & Password Policy ------------------------------------
section "4. Password & Authentication Policy"

LOGIN_DEFS="/etc/login.defs"
declare -A pw_checks=( ["PASS_MAX_DAYS"]="365" ["PASS_MIN_DAYS"]="7" ["PASS_WARN_AGE"]="7" )
for key in "${!pw_checks[@]}"; do
    val=$(grep "^${key}" "$LOGIN_DEFS" 2>/dev/null | awk '{print $2}')
    expected="${pw_checks[$key]}"
    if [[ "$val" -le "$expected" ]] 2>/dev/null; then
        log_pass "CIS 5.4.1: $key = $val"
        add_result "5.4.1" "$key" "PASS"
    else
        log_fail "CIS 5.4.1: $key = '${val:-not set}' (should be <= $expected)"
        add_result "5.4.1" "$key" "FAIL" "got ${val:-not set}"
    fi
done

# Check pam_pwquality
if grep -q "pam_pwquality" /etc/pam.d/common-password 2>/dev/null; then
    log_pass "CIS 5.3.1: pam_pwquality is configured"
    add_result "5.3.1" "pam_pwquality" "PASS"
else
    log_fail "CIS 5.3.1: pam_pwquality NOT configured"
    add_result "5.3.1" "pam_pwquality" "FAIL"
fi

# ---- 5. Firewall ------------------------------------------------------------
section "5. Firewall (UFW)"

if command -v ufw &>/dev/null; then
    UFW_STATUS=$(ufw status | head -1)
    if echo "$UFW_STATUS" | grep -q "active"; then
        log_pass "CIS 3.5.1: UFW is active"
        add_result "3.5.1" "UFW active" "PASS"
    else
        log_fail "CIS 3.5.1: UFW is NOT active"
        add_result "3.5.1" "UFW active" "FAIL"
    fi
else
    log_fail "CIS 3.5.1: UFW is NOT installed"
    add_result "3.5.1" "UFW installed" "FAIL"
fi

# ---- 6. Logging -------------------------------------------------------------
section "6. Logging & Auditing"

for svc in rsyslog auditd; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        log_pass "CIS 4.x: $svc is running"
        add_result "4.x" "$svc running" "PASS"
    else
        log_fail "CIS 4.x: $svc is NOT running"
        add_result "4.x" "$svc running" "FAIL"
    fi
done

# ---- 7. Kernel Parameters ---------------------------------------------------
section "7. Kernel Hardening (sysctl)"

declare -A kernel_checks=(
    ["net.ipv4.ip_forward"]="0"
    ["net.ipv4.conf.all.send_redirects"]="0"
    ["net.ipv4.conf.all.accept_source_route"]="0"
    ["net.ipv4.conf.all.accept_redirects"]="0"
    ["net.ipv4.conf.all.log_martians"]="1"
    ["net.ipv6.conf.all.disable_ipv6"]="1"
    ["kernel.randomize_va_space"]="2"
    ["fs.suid_dumpable"]="0"
)
for param in "${!kernel_checks[@]}"; do
    expected="${kernel_checks[$param]}"
    actual=$(sysctl -n "$param" 2>/dev/null || echo "not_set")
    if [[ "$actual" == "$expected" ]]; then
        log_pass "CIS 3.x: $param = $actual"
        add_result "3.x" "$param" "PASS"
    else
        log_fail "CIS 3.x: $param = '$actual' (expected: $expected)"
        add_result "3.x" "$param" "FAIL" "got '$actual'"
    fi
done

# ---- 8. File Permissions ----------------------------------------------------
section "8. Critical File Permissions"

declare -A perm_checks=(
    ["/etc/passwd"]="644"
    ["/etc/shadow"]="640"
    ["/etc/group"]="644"
    ["/etc/gshadow"]="640"
    ["/etc/crontab"]="600"
    ["/etc/ssh/sshd_config"]="600"
)
for file in "${!perm_checks[@]}"; do
    expected="${perm_checks[$file]}"
    if [[ -f "$file" ]]; then
        actual=$(stat -c "%a" "$file")
        if [[ "$actual" == "$expected" || "$actual" -le "$expected" ]] 2>/dev/null; then
            log_pass "CIS 6.x: $file permissions = $actual"
            add_result "6.x" "$file permissions" "PASS"
        else
            log_fail "CIS 6.x: $file permissions = $actual (expected: $expected)"
            add_result "6.x" "$file permissions" "FAIL" "got $actual"
        fi
    else
        log_warn "CIS 6.x: $file does not exist"
    fi
done

# ---- 9. Unnecessary Services ------------------------------------------------
section "9. Unnecessary Services"

UNWANTED_SVCS=(telnet rsh rlogin vsftpd xinetd nis talk)
for svc in "${UNWANTED_SVCS[@]}"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null || is_installed "$svc"; then
        log_fail "CIS 2.x: Service/package $svc is installed/running"
        add_result "2.x" "$svc disabled" "FAIL"
    else
        log_pass "CIS 2.x: Service/package $svc is not present"
        add_result "2.x" "$svc disabled" "PASS"
    fi
done

} | tee "$BASELINE_REPORT"

echo ""
echo -e "${GREEN}[AUDIT COMPLETE]${NC} Baseline report saved: $BASELINE_REPORT"
