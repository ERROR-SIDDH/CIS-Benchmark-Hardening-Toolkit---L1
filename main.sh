#!/bin/bash
# =============================================================================
# CIS Benchmark Hardening Tool - Main Entry Point
# Ubuntu 22.04 LTS | Level 1
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_DIR="$SCRIPT_DIR/reports"
LOG_FILE="$REPORT_DIR/hardening_$(date +%Y%m%d_%H%M%S).log"

source "$SCRIPT_DIR/utils/colors.sh"
source "$SCRIPT_DIR/utils/helpers.sh"

# ---- Preflight checks -------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR]${NC} This script must be run as root. Use: sudo bash main.sh"
    exit 1
fi

if ! grep -q "Ubuntu 22.04" /etc/os-release 2>/dev/null; then
    echo -e "${YELLOW}[WARN]${NC} This tool is designed for Ubuntu 22.04 LTS. Proceed with caution."
fi

mkdir -p "$REPORT_DIR"

# ---- Banner -----------------------------------------------------------------
clear
echo -e "${CYAN}"
cat << 'EOF'
  ██████╗██╗███████╗    ██╗  ██╗ █████╗ ██████╗ ██████╗ ███████╗███╗   ██╗██╗███╗   ██╗ ██████╗
 ██╔════╝██║██╔════╝    ██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝████╗  ██║██║████╗  ██║██╔════╝
 ██║     ██║███████╗    ███████║███████║██████╔╝██║  ██║█████╗  ██╔██╗ ██║██║██╔██╗ ██║██║  ███╗
 ██║     ██║╚════██║    ██╔══██║██╔══██║██╔══██╗██║  ██║██╔══╝  ██║╚██╗██║██║██║╚██╗██║██║   ██║
 ╚██████╗██║███████║    ██║  ██║██║  ██║██║  ██║██████╔╝███████╗██║ ╚████║██║██║ ╚████║╚██████╔╝
  ╚═════╝╚═╝╚══════╝    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝
EOF
echo -e "${NC}"
echo -e "${GREEN}  CIS Benchmark Level 1 Hardening Tool |by SIDHARTH M, Aksith Mahesh, Chinmaya Bhavana| Ubuntu 22.04 LTS${NC}"
echo -e "${CYAN}  ================================================================${NC}"
echo ""

log_info "Starting CIS  Hardening Tool"
log_info "Log file: $LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

# ---- Phase 1: Baseline Audit ------------------------------------------------
echo -e "\n${CYAN}[PHASE 1] Baseline Audit${NC}"
echo "================================================================"
bash "$SCRIPT_DIR/audit/baseline_audit.sh"

# ---- Phase 2: Hardening Engine ---------------------------------------------
echo -e "\n${CYAN}[PHASE 2] Hardening Engine${NC}"
echo "================================================================"
read -rp "$(echo -e ${YELLOW}Apply hardening? This will modify system settings. [y/N]: ${NC})" confirm
if [[ "$confirm" =~ ^[Yy]$ ]]; then
    bash "$SCRIPT_DIR/harden/harden_auth.sh"
    bash "$SCRIPT_DIR/harden/harden_ssh.sh"
    bash "$SCRIPT_DIR/harden/harden_filesystem.sh"
    bash "$SCRIPT_DIR/harden/harden_kernel.sh"
    bash "$SCRIPT_DIR/harden/harden_logging.sh"
    bash "$SCRIPT_DIR/harden/harden_firewall.sh"
    bash "$SCRIPT_DIR/harden/harden_services.sh"
else
    echo -e "${YELLOW}[SKIP]${NC} Hardening skipped by user."
fi

# ---- Phase 3: Compliance Validation ----------------------------------------
echo -e "\n${CYAN}[PHASE 3] Compliance Validation & Reporting${NC}"
echo "================================================================"
bash "$SCRIPT_DIR/audit/compliance_validator.sh"

echo -e "\n${GREEN}[DONE]${NC} CIS Hardening complete. Reports saved to: $REPORT_DIR"
