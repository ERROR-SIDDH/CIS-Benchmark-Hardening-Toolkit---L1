#!/bin/bash
# utils/rollback.sh
# Restore backed-up files from a specific backup date

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/utils/colors.sh"

BACKUP_BASE="/var/backups/cis-hardening"

echo -e "${CYAN}=== CIS Hardening Rollback Tool ===${NC}"
echo ""

# List available backup dates
if [[ ! -d "$BACKUP_BASE" ]]; then
    echo -e "${RED}No backups found at $BACKUP_BASE${NC}"
    exit 1
fi

echo "Available backup dates:"
ls "$BACKUP_BASE"
echo ""
read -rp "Enter backup date to restore (e.g., 20240115): " BDATE

BACKUP_DIR="$BACKUP_BASE/$BDATE"
if [[ ! -d "$BACKUP_DIR" ]]; then
    echo -e "${RED}Backup not found: $BACKUP_DIR${NC}"
    exit 1
fi

echo -e "${YELLOW}[WARNING]${NC} This will restore the following files:"
ls "$BACKUP_DIR"
echo ""
read -rp "Confirm rollback? [y/N]: " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Rollback cancelled."
    exit 0
fi

# Restore each .bak file to its original location
while IFS= read -r -d '' bakfile; do
    basename_stripped="${bakfile%.bak}"
    original_name="$(basename "$basename_stripped")"

    # Find original path by scanning common locations
    for dir in /etc /etc/ssh /etc/pam.d /etc/audit /etc/systemd; do
        if [[ -f "$dir/$original_name" ]]; then
            cp -p "$bakfile" "$dir/$original_name"
            echo -e "${GREEN}[RESTORED]${NC} $dir/$original_name"
            break
        fi
    done
done < <(find "$BACKUP_DIR" -name "*.bak" -print0)

echo ""
echo -e "${GREEN}Rollback complete. Consider rebooting the system.${NC}"
echo -e "${YELLOW}Run: sudo reboot${NC}"
