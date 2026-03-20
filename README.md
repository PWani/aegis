# AEGIS — Server Security Audit Dashboard

A browser-based security scanner and hardening tool that connects to Linux servers over SSH, runs comprehensive vulnerability assessments aligned with CIS Benchmarks, and provides one-click remediation for every finding.

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Flask](https://img.shields.io/badge/flask-web%20UI-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

---

## What It Does

AEGIS connects to any Linux server via SSH and performs a full security audit across 20+ categories, scoring the server out of 100 and presenting results in an interactive dashboard. Every finding includes an explanation of the risk, a CIS Benchmark reference where applicable, and an auto-generated fix command that can be applied with a single click.

### Scan Categories

- **Firewall (UFW)** — Status, default policies, rule audit, full management interface
- **Open Ports & Listening Services** — TCP/UDP listeners with process identification and risk classification
- **SSH Configuration** — Root login, password auth, key-only enforcement, protocol hardening
- **Fail2Ban** — Installation status, jail configuration, banned IP management
- **Authentication Logs** — Failed login analysis, top attacking IPs, successful root logins
- **SUID/SGID Binaries** — World-writable files and dangerous permission detection
- **SSL/TLS & Web Security** — Certificate expiry, missing HTTP security headers (HSTS, CSP, X-Frame-Options)
- **Application Security** — PostgreSQL trust auth, xRDP exposure, default credentials
- **Running Processes** — Detection of crypto miners, reverse shells, suspicious binaries
- **Systemd Services** — Role-aware classification of enabled services with risk ratings
- **Network Connections** — Established external connections with geolocation and reputation
- **Kernel Hardening (sysctl)** — ASLR, SYN flood protection, ICMP redirect handling, IP forwarding
- **Filesystem Security** — World-writable directories, /tmp mount options, noexec enforcement
- **Docker Security** — Daemon exposure, container privilege audit
- **Cron Jobs** — Suspicious scheduled task detection across all users
- **Password Policy** — Minimum length, complexity, aging rules via PAM
- **DNS Configuration** — Resolver validation
- **Audit Framework** — auditd status and rule coverage
- **AppArmor/SELinux** — MAC enforcement status and unconfined process detection
- **Sudoers Analysis** — NOPASSWD rules, wildcard abuse, dangerous command grants

### Additional Capabilities

- **External Exposure Scan** — Scans from your machine against the server's public IP to show what an attacker sees: open ports, HTTP headers, SSL configuration, DNS records, and SSH banner leakage
- **LAN Network Scanner** — ARP-based host discovery, port scanning, rogue device detection, and gateway analysis on the local subnet
- **UFW Firewall Manager** — Full CRUD interface for UFW rules, default policies, IP blocking, and enable/disable directly from the dashboard
- **Fail2Ban Manager** — View jail status, banned IPs, whitelist management, and one-click unban
- **Nginx Manager** — Install, enable/disable, create virtual hosts with reverse proxy and SSL, and edit site configurations
- **Role-Aware Scanning** — Server profiles (General, Web, Database, Mail, Bastion, Custom) adjust which services and ports are expected vs flagged
- **One-Click Fix & Undo** — Every finding has an auto-generated fix command and a corresponding undo command to roll back changes
- **Fix All** — Batch-apply all fixes for a scan section in one click
- **Scan History & Diff** — Compare current results to previous scans, track score changes over time
- **Encrypted Credential Storage** — Connection settings stored with Fernet encryption (PBKDF2-derived key), not plaintext
- **IP Blocking** — Block individual IPs or batch-block all top attackers via UFW

## Quick Start

### Prerequisites

- Python 3.8+
- SSH access to the target Linux server (key-based or password)
- `sudo` access on the target for full scan coverage

### Installation

```bash
git clone https://github.com/YOUR_USERNAME/aegis.git
cd aegis
pip install -r requirements.txt
```

### Usage

```bash
python aegis.py
```

This launches the dashboard at `http://localhost:5000`. Enter your server connection details in the browser to begin scanning.

**Options:**

| Flag | Description |
|---|---|
| `-p`, `--port` | Web UI port (default: 5000) |
| `--no-browser` | Don't auto-open browser on launch |

### LAN-Only Mode

Click "LAN Scan Only" on the login page to scan your local network without needing a server connection. This discovers hosts, open ports, and potential rogue devices on your subnet.

## How It Works

1. **Connect** — AEGIS establishes an SSH connection to the target server using key-based or password authentication, with multiplexed connections for performance
2. **Scan** — Runs 20+ security checks via SSH commands, collecting firewall rules, open ports, SSH config, running services, kernel parameters, and more
3. **Analyze** — Parses all output against CIS Benchmark baselines and a built-in risk taxonomy of services, ports, and kernel settings
4. **Score** — Produces a 0–100 security score weighted by severity (Critical, High, Medium, Low)
5. **Fix** — Generates remediation commands for every finding, executable with a single click and reversible with undo commands

## Platform Support

AEGIS runs on **Windows, macOS, and Linux** as the client machine. The target server must be a Linux system reachable over SSH. On Windows, the tool uses native SSH and handles subprocess lifecycle management including orphaned process cleanup.

## Security Notes

- Credentials are encrypted at rest using Fernet symmetric encryption with a PBKDF2-derived machine-specific key
- The web UI binds to `0.0.0.0` by default — restrict to `127.0.0.1` in production or use a firewall
- sudo passwords are transmitted over the existing SSH tunnel, never stored in plaintext
- All fix commands are executed via the authenticated SSH session with full audit logging

## License

MIT
