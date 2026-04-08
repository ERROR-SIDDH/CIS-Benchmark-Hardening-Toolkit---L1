#!/bin/bash
# utils/helpers.sh - Shared helper functions

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

# Logging
log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; WARN_COUNT=$((WARN_COUNT+1)); }
log_fail()  { echo -e "${RED}[FAIL]${NC}  $*"; FAIL_COUNT=$((FAIL_COUNT+1)); }
log_pass()  { echo -e "${GREEN}[PASS]${NC}  $*"; PASS_COUNT=$((PASS_COUNT+1)); }
log_apply() { echo -e "${CYAN}[APPLY]${NC} $*"; }

# Backup a file before modification
backup_file() {
    local file="$1"
    local backup_dir="/var/backups/cis-hardening/$(date +%Y%m%d)"
    mkdir -p "$backup_dir"
    if [[ -f "$file" ]]; then
        cp -p "$file" "$backup_dir/$(basename "$file").bak" 2>/dev/null || true
        echo -e "${BLUE}[BAK]${NC}   Backed up: $file -> $backup_dir"
    fi
}

# Append to file if line not already present
append_if_missing() {
    local line="$1"
    local file="$2"
    grep -qF -- "$line" "$file" 2>/dev/null || echo "$line" >> "$file"
}

# Set a key=value config (handles both = and space delimiters)
set_config() {
    local key="$1"
    local value="$2"
    local file="$3"
    local delimiter="${4:- }"   # default space delimiter

    backup_file "$file"
    if grep -qE "^#?\s*${key}" "$file" 2>/dev/null; then
        sed -i "s|^#\?\s*${key}.*|${key}${delimiter}${value}|" "$file"
    else
        echo "${key}${delimiter}${value}" >> "$file"
    fi
}

# Check if a package is installed
is_installed() {
    dpkg -l "$1" 2>/dev/null | grep -q "^ii"
}

# Print section header
section() {
    echo -e "\n${BOLD}${MAGENTA}--- $* ---${NC}"
}

# Print compliance result to JSON (appends to report file)
REPORT_JSON="/tmp/cis_results.json"
init_report() {
    echo '{"results":[]}' > "$REPORT_JSON"
}

add_result() {
    local cis_id="$1"
    local desc="$2"
    local status="$3"   # PASS | FAIL | WARN
    local detail="${4:-}"
    local tmp
    tmp=$(mktemp)
    python3 -c "
import json, sys
with open('$REPORT_JSON') as f:
    d = json.load(f)
d['results'].append({'id':'$cis_id','desc':'$desc','status':'$status','detail':'$detail'})
with open('$REPORT_JSON','w') as f:
    json.dump(d, f, indent=2)
" 2>/dev/null || true
}
