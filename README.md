# CIS Benchmark Hardening Toolkit

<p align="center">
	<strong>Enterprise-style Ubuntu 22.04 hardening with audit, remediation, rollback, and compliance reporting.</strong>
</p>

<p align="center">
	<img alt="Platform" src="https://img.shields.io/badge/platform-Ubuntu%2022.04-0D4A72?style=for-the-badge">
	<img alt="Profile" src="https://img.shields.io/badge/CIS-Level%201-197A4A?style=for-the-badge">
	<img alt="Language" src="https://img.shields.io/badge/shell-bash-A86A00?style=for-the-badge">
</p>

## Why This Project 

This toolkit helps you harden Ubuntu hosts against the CIS Benchmark (Level 1) using a clear, modular workflow:

1. Baseline audit
2. Guided hardening execution
3. Post-hardening compliance validation
4. Text + HTML reporting
5. Rollback support from backups

It is designed for security labs, VM baselines, and infrastructure teams that need repeatable hardening with clear visibility.

## Feature Highlights

- Full hardening pipeline orchestrated by one entry point
- Modular security scripts for auth, SSH, kernel, firewall, logging, services, and filesystem
- Baseline and post-hardening validation
- Professional HTML compliance report with score and control-level details
- Backup-first approach to reduce recovery risk
- Standalone module execution for targeted operations

## Project Layout

```text
.
├── main.sh                        # Main execution workflow
├── helpers.sh                     # Shared shell helpers
├── rollback.sh                    # Restore backed up config files
├── audit/
│   ├── baseline_audit.sh          # Pre-hardening audit checks
│   └── compliance_validator.sh    # Post-hardening scoring + HTML/TXT reports
├── harden/
│   ├── harden_auth.sh             # PAM and password/account controls
│   ├── harden_ssh.sh              # OpenSSH server hardening
│   ├── harden_filesystem.sh       # /tmp + file permission controls
│   ├── harden_kernel.sh           # sysctl + module hardening
│   ├── harden_logging.sh          # auditd + rsyslog policies
│   ├── harden_firewall.sh         # UFW baseline policies
│   └── harden_services.sh         # Remove/disable risky services
└── utils/
    └── colors.sh                  # Terminal output styling helpers
```

## Quick Start

### 1. Clone the repository

```bash
git clone <your-repo-url> cis-hardening
cd cis-hardening
```

### 2. Make scripts executable

```bash
chmod +x *.sh audit/*.sh harden/*.sh utils/*.sh
```

### 3. Run the full workflow

```bash
sudo bash main.sh
```

During execution, the tool performs:

1. Baseline audit
2. Confirmation prompt before modifications
3. Hardening module execution
4. Compliance validation
5. Report generation in `reports/`

## Run Only What You Need

```bash
# Audit only
sudo bash audit/baseline_audit.sh

# Targeted hardening examples
sudo bash harden/harden_ssh.sh
sudo bash harden/harden_kernel.sh
sudo bash harden/harden_firewall.sh

# Post-hardening validation only
sudo bash audit/compliance_validator.sh
```

## Report Output

Each run generates timestamped reports in the `reports/` directory:

- `compliance_report_<timestamp>.txt`
- `compliance_report_<timestamp>.html`
- `hardening_<timestamp>.log`

To preview reports locally:

```bash
python3 -m http.server 8080 --directory reports/
# open http://localhost:8080
```

## Rollback Strategy

Before changes are applied, backups are stored under:

```text
/var/backups/cis-hardening/YYYYMMDD/
```

To restore:

```bash
sudo bash rollback.sh
```

## Control Coverage (High Level)

| Module | CIS Sections Covered |
|---|---|
| Authentication | 5.3, 5.4 |
| SSH | 5.2 |
| Filesystem | 1.1, 6.1 |
| Kernel / Network | 1.5, 3.1, 3.2, 3.3 |
| Logging / Auditing | 4.1, 4.2 |
| Firewall | 3.5 |
| Services | 2.x |
| AppArmor / Sudo checks | 1.6, 5.3 |

## Requirements

- Ubuntu 22.04 LTS (recommended and tested)
- Root privileges (`sudo`)
- Core Linux tooling: `bash`, `systemctl`, `sysctl`, `ufw`, `apt`, `grep`, `awk`

## Operational Notes

- This tool modifies security-sensitive system settings.
- Always test in a non-production VM before applying in production.
- If your environment requires IPv6, review IPv6-related hardening settings before execution.
- Keep console access ready during first runs to avoid remote lockout scenarios.

## Disclaimer

This project provides automated hardening guidance and controls, not a compliance certification.
Validate final settings against your organization policy and the official CIS benchmark documentation
