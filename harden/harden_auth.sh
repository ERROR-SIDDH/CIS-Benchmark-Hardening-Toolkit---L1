#!/bin/bash
# harden/harden_auth.sh
# CIS Level 1: Authentication & Password Policy Hardening

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/utils/colors.sh"
source "$SCRIPT_DIR/utils/helpers.sh"

section "Hardening: Authentication & Password Policy"

# ---- Install pam_pwquality --------------------------------------------------
log_apply "Installing libpam-pwquality..."
apt-get install -y libpam-pwquality &>/dev/null
log_pass "libpam-pwquality installed"

# ---- Configure password quality ---------------------------------------------
PWQUALITY_CONF="/etc/security/pwquality.conf"
backup_file "$PWQUALITY_CONF"

declare -A pw_quality=(
    ["minlen"]="14"
    ["dcredit"]="-1"
    ["ucredit"]="-1"
    ["ocredit"]="-1"
    ["lcredit"]="-1"
    ["minclass"]="4"
    ["maxrepeat"]="3"
    ["gecoscheck"]="1"
    ["dictcheck"]="1"
)
for key in "${!pw_quality[@]}"; do
    set_config "$key" "${pw_quality[$key]}" "$PWQUALITY_CONF" " = "
    log_apply "pwquality: $key = ${pw_quality[$key]}"
done
log_pass "Password quality policy applied"

# ---- PAM common-password ----------------------------------------------------
PAM_PASSWORD="/etc/pam.d/common-password"
backup_file "$PAM_PASSWORD"

# Ensure pam_pwquality is in the stack with retry=3
if ! grep -q "pam_pwquality" "$PAM_PASSWORD"; then
    sed -i '1s/^/password requisite pam_pwquality.so retry=3\n/' "$PAM_PASSWORD"
fi

# Add remember=5 to pam_unix to prevent password reuse
if grep -q "pam_unix.so" "$PAM_PASSWORD"; then
    sed -i '/pam_unix.so/ s/$/ remember=5/' "$PAM_PASSWORD"
    # Avoid duplicating remember
    sed -i 's/\(remember=[0-9]*\)\( remember=[0-9]*\)\+/\1/' "$PAM_PASSWORD"
fi
log_pass "PAM common-password configured"

# ---- PAM common-auth: account lockout ---------------------------------------
PAM_AUTH="/etc/pam.d/common-auth"
backup_file "$PAM_AUTH"

# Install pam_tally2 / pam_faillock (faillock preferred on 22.04)
if ! grep -q "pam_faillock" "$PAM_AUTH"; then
    cat >> "$PAM_AUTH" << 'EOF'

# CIS 5.3.2: Account lockout after 5 failed attempts
auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900
auth [success=1 default=bad] pam_unix.so
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900
EOF
fi
log_pass "Account lockout policy applied (5 attempts, 15 min lockout)"

# ---- PAM su restriction -----------------------------------------------------
PAM_SU="/etc/pam.d/su"
backup_file "$PAM_SU"

# Restrict su to wheel/sudo group members
if ! grep -q "pam_wheel" "$PAM_SU"; then
    sed -i '1s/^/auth required pam_wheel.so use_uid\n/' "$PAM_SU"
fi
log_pass "su command restricted to wheel group"

# ---- /etc/login.defs --------------------------------------------------------
LOGIN_DEFS="/etc/login.defs"
backup_file "$LOGIN_DEFS"

set_config "PASS_MAX_DAYS" "365"  "$LOGIN_DEFS"
set_config "PASS_MIN_DAYS" "7"    "$LOGIN_DEFS"
set_config "PASS_WARN_AGE" "7"    "$LOGIN_DEFS"
set_config "LOGIN_RETRIES" "5"    "$LOGIN_DEFS"
set_config "LOGIN_TIMEOUT" "60"   "$LOGIN_DEFS"
set_config "UMASK"         "027"  "$LOGIN_DEFS"
set_config "SHA_CRYPT_MIN_ROUNDS" "10000" "$LOGIN_DEFS"
set_config "SHA_CRYPT_MAX_ROUNDS" "65536" "$LOGIN_DEFS"
log_pass "login.defs password aging and umask set"

# ---- Enforce password aging on existing users --------------------------------
log_apply "Enforcing password aging on existing non-system accounts..."
while IFS=: read -r user _ uid _ _ _ shell; do
    if [[ "$uid" -ge 1000 && "$shell" != "/usr/sbin/nologin" && "$shell" != "/bin/false" ]]; then
        chage --maxdays 365 --mindays 7 --warndays 7 "$user" 2>/dev/null || true
        log_apply "  Password aging applied to user: $user"
    fi
done < /etc/passwd
log_pass "Password aging applied to all active users"

# ---- Default umask ----------------------------------------------------------
backup_file "/etc/profile"
append_if_missing "umask 027" "/etc/profile"
backup_file "/etc/bash.bashrc"
append_if_missing "umask 027" "/etc/bash.bashrc"
log_pass "Default umask set to 027"

# ---- Disable root account login ---------------------------------------------
# We lock root password but keep sudo access available
passwd -l root &>/dev/null && log_pass "Root account password locked (sudo still works)" || log_warn "Could not lock root password"

echo -e "\n${GREEN}[AUTH HARDENING COMPLETE]${NC}"
