#!/bin/bash
# audit/compliance_validator.sh
# Post-hardening compliance scan with scoring and HTML report generation

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/utils/colors.sh"
source "$SCRIPT_DIR/utils/helpers.sh"

REPORT_DIR="$SCRIPT_DIR/reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
HTML_REPORT="$REPORT_DIR/compliance_report_$TIMESTAMP.html"
TXT_REPORT="$REPORT_DIR/compliance_report_$TIMESTAMP.txt"
mkdir -p "$REPORT_DIR"

PASS=0
FAIL=0
WARN=0

# Helper for this script
check() {
    local id="$1"
    local desc="$2"
    local cmd="$3"

    if eval "$cmd" &>/dev/null; then
        echo -e "${GREEN}[PASS]${NC} [$id] $desc"
        PASS=$((PASS+1))
        echo "PASS|$id|$desc" >> /tmp/cis_val_results.txt
    else
        echo -e "${RED}[FAIL]${NC} [$id] $desc"
        FAIL=$((FAIL+1))
        echo "FAIL|$id|$desc" >> /tmp/cis_val_results.txt
    fi
}

warn_check() {
    local id="$1"
    local desc="$2"
    local cmd="$3"

    if eval "$cmd" &>/dev/null; then
        echo -e "${GREEN}[PASS]${NC} [$id] $desc"
        PASS=$((PASS+1))
        echo "PASS|$id|$desc" >> /tmp/cis_val_results.txt
    else
        echo -e "${YELLOW}[WARN]${NC} [$id] $desc"
        WARN=$((WARN+1))
        echo "WARN|$id|$desc" >> /tmp/cis_val_results.txt
    fi
}

# Reset results file
> /tmp/cis_val_results.txt

echo "================================================================"
echo " POST-HARDENING COMPLIANCE VALIDATION"
echo " Host: $(hostname) | Date: $(date)"
echo "================================================================"

# ---- Kernel Modules ---------------------------------------------------------
section "1. Filesystem Modules"
for mod in cramfs freevxfs jffs2 hfs hfsplus squashfs udf dccp sctp rds tipc; do
    check "1.1.x" "Module $mod is disabled" "! modprobe --dry-run $mod 2>&1 | grep -q 'insmod'"
done

# ---- /tmp -------------------------------------------------------------------
section "1.1 /tmp Configuration"
warn_check "1.1.2" "/tmp is a separate partition" "mount | grep -q ' on /tmp '"
check "1.1.3" "/tmp mounted nodev"   "mount | grep ' on /tmp ' | grep -q nodev"
check "1.1.4" "/tmp mounted nosuid"  "mount | grep ' on /tmp ' | grep -q nosuid"
check "1.1.5" "/tmp mounted noexec"  "mount | grep ' on /tmp ' | grep -q noexec"

# ---- Package Management -----------------------------------------------------
section "1.9 Patches & Updates"
check "1.9" "No pending updates" "[ \$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst') -eq 0 ]"

# ---- SSH --------------------------------------------------------------------
section "5.2 SSH Configuration"
SSH_CFG="/etc/ssh/sshd_config"
check "5.2.1"  "SSH Protocol 2"                  "grep -qiE '^Protocol\s+2' $SSH_CFG"
check "5.2.2"  "SSH LogLevel VERBOSE"             "grep -qiE '^LogLevel\s+(VERBOSE|INFO)' $SSH_CFG"
check "5.2.4"  "SSH X11Forwarding disabled"       "grep -qiE '^X11Forwarding\s+no' $SSH_CFG"
check "5.2.5"  "SSH MaxAuthTries <= 4"            "[ \$(grep -iE '^MaxAuthTries' $SSH_CFG | awk '{print \$2}') -le 4 ]"
check "5.2.6"  "SSH IgnoreRhosts yes"             "grep -qiE '^IgnoreRhosts\s+yes' $SSH_CFG"
check "5.2.7"  "SSH HostbasedAuth disabled"       "grep -qiE '^HostbasedAuthentication\s+no' $SSH_CFG"
check "5.2.8"  "SSH PermitRootLogin disabled"     "grep -qiE '^PermitRootLogin\s+no' $SSH_CFG"
check "5.2.9"  "SSH PermitEmptyPasswords no"      "grep -qiE '^PermitEmptyPasswords\s+no' $SSH_CFG"
check "5.2.10" "SSH PermitUserEnvironment no"     "grep -qiE '^PermitUserEnvironment\s+no' $SSH_CFG"
check "5.2.14" "SSH ClientAliveInterval set"      "grep -qiE '^ClientAliveInterval\s+[1-9]' $SSH_CFG"
check "5.2.15" "SSH ClientAliveCountMax = 0"      "grep -qiE '^ClientAliveCountMax\s+0' $SSH_CFG"
check "5.2.16" "SSH LoginGraceTime <= 60"         "[ \$(grep -iE '^LoginGraceTime' $SSH_CFG | awk '{print \$2}') -le 60 ]"
check "5.2.21" "SSH Banner configured"            "grep -qiE '^Banner' $SSH_CFG"

# ---- Password Policy --------------------------------------------------------
section "5.4 Password Policy"
check "5.4.1.1" "PASS_MAX_DAYS <= 365"  "[ \$(grep '^PASS_MAX_DAYS' /etc/login.defs | awk '{print \$2}') -le 365 ]"
check "5.4.1.2" "PASS_MIN_DAYS >= 7"   "[ \$(grep '^PASS_MIN_DAYS' /etc/login.defs | awk '{print \$2}') -ge 7 ]"
check "5.4.1.4" "PASS_WARN_AGE >= 7"   "[ \$(grep '^PASS_WARN_AGE' /etc/login.defs | awk '{print \$2}') -ge 7 ]"
check "5.3.1"   "pam_pwquality installed" "grep -q pam_pwquality /etc/pam.d/common-password"
check "5.3.3"   "Password reuse limited (remember=5)" "grep -q 'remember=' /etc/pam.d/common-password"
check "5.4.2"   "Root account locked"  "passwd -S root | grep -qE '^root L'"

# ---- Kernel Parameters ------------------------------------------------------
section "3.x Kernel Network Hardening"
check "3.1.1" "IP forwarding disabled"              "[ \$(sysctl -n net.ipv4.ip_forward) = '0' ]"
check "3.1.2" "Send redirects disabled"             "[ \$(sysctl -n net.ipv4.conf.all.send_redirects) = '0' ]"
check "3.2.1" "Source routing disabled"             "[ \$(sysctl -n net.ipv4.conf.all.accept_source_route) = '0' ]"
check "3.2.2" "ICMP redirects disabled"             "[ \$(sysctl -n net.ipv4.conf.all.accept_redirects) = '0' ]"
check "3.2.4" "Martians logged"                     "[ \$(sysctl -n net.ipv4.conf.all.log_martians) = '1' ]"
check "3.2.5" "Broadcast ICMP ignored"              "[ \$(sysctl -n net.ipv4.icmp_echo_ignore_broadcasts) = '1' ]"
check "3.2.7" "TCP SYN cookies enabled"             "[ \$(sysctl -n net.ipv4.tcp_syncookies) = '1' ]"
check "3.3.1" "IPv6 disabled"                       "[ \$(sysctl -n net.ipv6.conf.all.disable_ipv6) = '1' ]"
check "1.5.1" "ASLR enabled"                        "[ \$(sysctl -n kernel.randomize_va_space) = '2' ]"
check "1.5.4" "Core dumps restricted"               "[ \$(sysctl -n fs.suid_dumpable) = '0' ]"
check "3.x"   "dmesg restricted"                    "[ \$(sysctl -n kernel.dmesg_restrict) = '1' ]"

# ---- Firewall ---------------------------------------------------------------
section "3.5 Firewall"
check "3.5.1.1" "UFW installed"            "command -v ufw"
check "3.5.1.2" "UFW active"              "ufw status | grep -q 'Status: active'"
check "3.5.1.3" "UFW default deny inbound" "ufw status verbose | grep -q 'Default: deny (incoming)'"

# ---- Logging & Auditing -----------------------------------------------------
section "4.x Logging & Auditing"
check "4.1.1"  "auditd installed"       "command -v auditd"
check "4.1.2"  "auditd running"         "systemctl is-active auditd"
check "4.2.1"  "rsyslog installed"      "command -v rsyslogd"
check "4.2.2"  "rsyslog running"        "systemctl is-active rsyslog"
check "4.2.3"  "rsyslog file perms"     "grep -q 'FileCreateMode 0640' /etc/rsyslog.conf"
check "4.1.17" "Audit rules immutable"  "auditctl -l 2>/dev/null | grep -q '\-e 2'"

# ---- File Permissions -------------------------------------------------------
section "6.x File Permissions"
check "6.1.2" "/etc/passwd perms 644"     "[ \$(stat -c '%a' /etc/passwd) = '644' ]"
check "6.1.3" "/etc/shadow perms <= 640"  "[ \$(stat -c '%a' /etc/shadow) -le 640 ]"
check "6.1.4" "/etc/group perms 644"      "[ \$(stat -c '%a' /etc/group) = '644' ]"
check "6.1.5" "/etc/gshadow perms <= 640" "[ \$(stat -c '%a' /etc/gshadow) -le 640 ]"
check "6.1.9" "World-writable files absent" "[ \$(find / -xdev -type f -perm -0002 2>/dev/null | grep -vc proc) -eq 0 ]"

# ---- Services ---------------------------------------------------------------
section "2.x Unnecessary Services"
for svc in telnet rsh vsftpd xinetd nis talk; do
    check "2.x" "$svc not running/installed" "! systemctl is-active $svc 2>/dev/null && ! dpkg -l $svc 2>/dev/null | grep -q '^ii'"
done
check "2.2.15" "CUPS disabled" "! systemctl is-active cups"
check "2.3.1"  "rpcbind disabled" "! systemctl is-active rpcbind"

# ---- AppArmor ---------------------------------------------------------------
section "1.6 AppArmor"
check "1.6.1" "AppArmor installed" "command -v aa-status"
check "1.6.2" "AppArmor enabled"   "systemctl is-active apparmor"

# ---- Sudo -------------------------------------------------------------------
section "5.3 Sudo"
check "5.3.x" "sudo installed"    "command -v sudo"
check "5.3.x" "sudo log_input"    "grep -q 'log_input' /etc/sudoers"
check "5.3.x" "sudo use_pty"      "grep -q 'use_pty' /etc/sudoers"

# ---- Score Calculation ------------------------------------------------------
TOTAL=$((PASS + FAIL + WARN))
SCORE=0
[[ $TOTAL -gt 0 ]] && SCORE=$(( (PASS * 100) / TOTAL ))

echo ""
echo "================================================================"
echo " COMPLIANCE SUMMARY"
echo "================================================================"
echo -e " ${GREEN}PASS : $PASS${NC}"
echo -e " ${RED}FAIL : $FAIL${NC}"
echo -e " ${YELLOW}WARN : $WARN${NC}"
echo -e " TOTAL: $TOTAL"
echo ""

if [[ $SCORE -ge 90 ]]; then COLOR="${GREEN}"
elif [[ $SCORE -ge 70 ]]; then COLOR="${YELLOW}"
else COLOR="${RED}"; fi

echo -e " ${BOLD}CIS Compliance Score: ${COLOR}${SCORE}%${NC}"
echo "================================================================"

# ---- Generate Text Report ---------------------------------------------------
{
    echo "CIS COMPLIANCE REPORT"
    echo "Host: $(hostname)"
    echo "Date: $(date)"
    echo "Score: $SCORE% | PASS: $PASS | FAIL: $FAIL | WARN: $WARN"
    echo ""
    cat /tmp/cis_val_results.txt
} > "$TXT_REPORT"

# ---- Generate HTML Report ---------------------------------------------------
if [[ $SCORE -ge 90 ]]; then
        SCORE_CLASS="excellent"
        SCORE_LABEL="Excellent"
elif [[ $SCORE -ge 70 ]]; then
        SCORE_CLASS="moderate"
        SCORE_LABEL="Moderate"
else
        SCORE_CLASS="critical"
        SCORE_LABEL="Needs Attention"
fi

PASS_PCT=0
FAIL_PCT=0
WARN_PCT=0
if [[ $TOTAL -gt 0 ]]; then
        PASS_PCT=$(( (PASS * 100) / TOTAL ))
        FAIL_PCT=$(( (FAIL * 100) / TOTAL ))
        WARN_PCT=$(( (WARN * 100) / TOTAL ))
fi

cat > "$HTML_REPORT" << HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CIS Compliance Report - $(hostname)</title>
<style>
    @import url('https://fonts.googleapis.com/css2?family=Manrope:wght@400;600;700;800&display=swap');

    :root {
        --bg: #f3f5f7;
        --paper: #ffffff;
        --ink: #10212f;
        --muted: #5b6b78;
        --line: #d8e0e7;
        --brand: #0d4a72;
        --pass: #197a4a;
        --fail: #b9382a;
        --warn: #a86a00;
        --pass-bg: #eaf8f0;
        --fail-bg: #fcedea;
        --warn-bg: #fff6e7;
    }

    * { box-sizing: border-box; }

    body {
        margin: 0;
        font-family: 'Manrope', 'Segoe UI', sans-serif;
        color: var(--ink);
        background:
            radial-gradient(circle at 100% 0%, #d9edf7 0, transparent 34%),
            radial-gradient(circle at 0% 100%, #e7f5ec 0, transparent 42%),
            var(--bg);
        padding: 24px;
    }

    .container {
        max-width: 1120px;
        margin: 0 auto;
    }

    .hero {
        background: linear-gradient(135deg, #08304a 0%, #11577b 50%, #2979a7 100%);
        color: #f9fdff;
        border-radius: 16px;
        padding: 30px;
        box-shadow: 0 14px 36px rgba(17, 72, 103, 0.26);
    }

    .hero h1 {
        margin: 0;
        font-size: clamp(1.4rem, 2.4vw, 2rem);
        letter-spacing: 0.2px;
        font-weight: 800;
    }

    .hero .subtitle {
        margin-top: 10px;
        color: #d2ecfb;
        font-size: 0.98rem;
    }

    .meta-grid {
        margin-top: 20px;
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        gap: 10px;
    }

    .meta-item {
        background: rgba(255, 255, 255, 0.14);
        border: 1px solid rgba(255, 255, 255, 0.26);
        border-radius: 10px;
        padding: 10px 12px;
        font-size: 0.9rem;
    }

    .label {
        font-weight: 700;
        color: #d6efff;
        margin-right: 6px;
    }

    .main-grid {
        margin-top: 18px;
        display: grid;
        grid-template-columns: minmax(260px, 320px) 1fr;
        gap: 16px;
    }

    .panel {
        background: var(--paper);
        border: 1px solid var(--line);
        border-radius: 14px;
        box-shadow: 0 8px 22px rgba(15, 39, 57, 0.08);
    }

    .score-panel {
        padding: 22px;
        text-align: center;
    }

    .score-panel h2 {
        margin: 0;
        color: var(--muted);
        font-size: 0.95rem;
        text-transform: uppercase;
        letter-spacing: 0.08em;
    }

    .score {
        margin-top: 10px;
        font-size: clamp(2.3rem, 6.5vw, 3.5rem);
        line-height: 1;
        font-weight: 800;
    }

    .score.excellent { color: var(--pass); }
    .score.moderate { color: var(--warn); }
    .score.critical { color: var(--fail); }

    .score-tag {
        display: inline-block;
        margin-top: 8px;
        border-radius: 999px;
        padding: 5px 12px;
        font-size: 0.82rem;
        font-weight: 700;
        border: 1px solid var(--line);
        color: var(--muted);
        background: #f7fafc;
    }

    .breakdown {
        padding: 16px;
    }

    .breakdown h3 {
        margin: 0 0 10px;
        font-size: 0.98rem;
        color: var(--ink);
    }

    .row {
        margin-bottom: 10px;
    }

    .row-head {
        display: flex;
        justify-content: space-between;
        font-size: 0.86rem;
        color: var(--muted);
        margin-bottom: 4px;
    }

    .bar {
        width: 100%;
        height: 8px;
        border-radius: 999px;
        background: #ebf1f5;
        overflow: hidden;
    }

    .fill { height: 100%; border-radius: 999px; }
    .fill.pass { background: linear-gradient(90deg, #26935d, #51bc82); width: ${PASS_PCT}%; }
    .fill.fail { background: linear-gradient(90deg, #cd4c3e, #e67b70); width: ${FAIL_PCT}%; }
    .fill.warn { background: linear-gradient(90deg, #b77a10, #d8a64a); width: ${WARN_PCT}%; }

    .table-panel { padding: 0; overflow: hidden; }

    .table-title {
        padding: 14px 16px;
        border-bottom: 1px solid var(--line);
        font-weight: 700;
        color: var(--ink);
        background: #f9fbfd;
    }

    .table-wrap { overflow-x: auto; }

    table {
        width: 100%;
        border-collapse: collapse;
        min-width: 700px;
    }

    th, td {
        padding: 11px 14px;
        text-align: left;
        font-size: 0.92rem;
    }

    th {
        color: #20445c;
        background: #edf5fa;
        font-size: 0.82rem;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        border-bottom: 1px solid var(--line);
    }

    td {
        border-bottom: 1px solid #edf2f7;
        color: #1e2f3d;
    }

    .badge {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: 64px;
        padding: 4px 10px;
        border-radius: 999px;
        font-size: 0.76rem;
        font-weight: 800;
        letter-spacing: 0.04em;
    }

    .badge.pass { background: var(--pass-bg); color: var(--pass); }
    .badge.fail { background: var(--fail-bg); color: var(--fail); }
    .badge.warn { background: var(--warn-bg); color: var(--warn); }

    .pass-row { border-left: 4px solid #52b888; }
    .fail-row { border-left: 4px solid #dc7166; }
    .warn-row { border-left: 4px solid #dcb56a; }

    footer {
        margin-top: 14px;
        text-align: right;
        color: #6a7c8a;
        font-size: 0.8rem;
    }

    @media (max-width: 960px) {
        .main-grid { grid-template-columns: 1fr; }
        body { padding: 14px; }
        .hero { padding: 20px; }
    }
</style>
</head>
<body>
<div class="container">
    <section class="hero">
        <h1>CIS Benchmark Level 1 Compliance Report</h1>
        <div class="subtitle">Automated post-hardening validation and scoring summary</div>
        <div class="meta-grid">
            <div class="meta-item"><span class="label">Host:</span> $(hostname)</div>
            <div class="meta-item"><span class="label">OS:</span> $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')</div>
            <div class="meta-item"><span class="label">Kernel:</span> $(uname -r)</div>
            <div class="meta-item"><span class="label">Generated:</span> $(date)</div>
        </div>
    </section>

    <section class="main-grid">
        <article class="panel score-panel">
            <h2>Compliance Score</h2>
            <div class="score $SCORE_CLASS">${SCORE}%</div>
            <div class="score-tag">$SCORE_LABEL</div>
        </article>

        <article class="panel breakdown">
            <h3>Result Breakdown (${TOTAL} checks)</h3>
            <div class="row">
                <div class="row-head"><span>PASS</span><span>${PASS} (${PASS_PCT}%)</span></div>
                <div class="bar"><div class="fill pass"></div></div>
            </div>
            <div class="row">
                <div class="row-head"><span>FAIL</span><span>${FAIL} (${FAIL_PCT}%)</span></div>
                <div class="bar"><div class="fill fail"></div></div>
            </div>
            <div class="row">
                <div class="row-head"><span>WARN</span><span>${WARN} (${WARN_PCT}%)</span></div>
                <div class="bar"><div class="fill warn"></div></div>
            </div>
        </article>
    </section>

    <section class="panel table-panel">
        <div class="table-title">Detailed Control Results</div>
        <div class="table-wrap">
            <table>
            <thead><tr><th>Status</th><th>CIS ID</th><th>Description</th></tr></thead>
            <tbody>
HTMLEOF

while IFS='|' read -r status id desc; do
    lower_status=$(echo "$status" | tr '[:upper:]' '[:lower:]')
    echo "<tr class=\"${lower_status}-row\"><td><span class=\"badge ${lower_status}\">$status</span></td><td>$id</td><td>$desc</td></tr>" >> "$HTML_REPORT"
done < /tmp/cis_val_results.txt

cat >> "$HTML_REPORT" << HTMLEOF
</tbody>
</table>
</div>
</section>
<footer>Generated by CIS Hardening Tool v1.0 on $(date)</footer>
</div>
</body>
</html>
HTMLEOF

chmod 644 "$HTML_REPORT"
if [[ -n "${SUDO_USER:-}" ]]; then
    chown "$SUDO_USER:$SUDO_USER" "$HTML_REPORT"
fi

echo ""
log_pass "Text report: $TXT_REPORT"
log_pass "HTML report: $HTML_REPORT"
echo -e "\n${CYAN}Open the HTML report in a browser:${NC}"
echo "  python3 -m http.server 8080 --directory $REPORT_DIR"
echo "  Then visit: http://localhost:8080/$(basename "$HTML_REPORT")"

# Cleanup
rm -f /tmp/cis_val_results.txt
