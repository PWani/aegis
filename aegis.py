#!/usr/bin/env python3
"""
AEGIS v5 — Comprehensive Server Security Audit Dashboard
Full-featured browser-based security scanner with CIS Benchmark alignment,
role-aware service classification, encrypted credential storage, and
proper subprocess lifecycle management.

Changes from v4:
  • CIS Benchmark-aligned checks with control IDs and references
  • Role-aware server profiles (web, database, mail, bastion, general)
  • Encrypted credential storage via Fernet (not base64 obfuscation)
  • Per-section "requires sudo" indicators instead of silent failure
  • Expanded service/port risk taxonomy from CIS and NIST sources
  • Proper subprocess cleanup on exit (no orphaned PowerShell/SSH)
  • Scan history with diff between runs
  • Score adjusted for unchecked sections

Usage:
    pip install flask cryptography
    python aegis_v5.py
    → Opens http://localhost:5000 — enter your server details in the browser
"""

import subprocess, sys, os, re, json, argparse, platform, threading, webbrowser, time, base64, hashlib
import signal, atexit
from datetime import datetime
from pathlib import Path

try:
    from flask import Flask, Response, jsonify, request
except ImportError:
    print("Install Flask: pip install flask"); sys.exit(1)

IS_WIN = platform.system() == "Windows"
app = Flask(__name__)
app.secret_key = os.urandom(24)

# ═══════════════════════════════════════════════════
#  SUBPROCESS LIFECYCLE MANAGEMENT
# ═══════════════════════════════════════════════════
_active_subprocesses = []
_subprocess_lock = threading.Lock()

def _track_subprocess(proc):
    with _subprocess_lock:
        _active_subprocesses.append(proc)

def _untrack_subprocess(proc):
    with _subprocess_lock:
        if proc in _active_subprocesses:
            _active_subprocesses.remove(proc)

def _cleanup_subprocesses():
    with _subprocess_lock:
        for proc in _active_subprocesses:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except:
                try: proc.kill()
                except: pass
        _active_subprocesses.clear()

atexit.register(_cleanup_subprocesses)

def _signal_handler(signum, frame):
    _cleanup_subprocesses()
    if SSH_CONN:
        try: SSH_CONN.cleanup()
        except: pass
    # Redirect stdout/stderr to devnull to prevent daemon thread write crashes
    try:
        devnull = open(os.devnull, 'w')
        sys.stdout = devnull
        sys.stderr = devnull
    except: pass
    os._exit(0)

for _sig in (signal.SIGTERM, signal.SIGINT):
    try: signal.signal(_sig, _signal_handler)
    except: pass
if hasattr(signal, 'SIGBREAK'):
    try: signal.signal(signal.SIGBREAK, _signal_handler)
    except: pass

# ═══════════════════════════════════════════════════
#  ENCRYPTED CONFIG STORAGE
# ═══════════════════════════════════════════════════
CONFIG_DIR = Path.home() / ".aegis"
CONFIG_FILE = CONFIG_DIR / "config.json"
HISTORY_DIR = CONFIG_DIR / "history"

def _derive_key():
    """Derive a machine+user-specific Fernet key for encrypting credentials."""
    salt = (platform.node() + os.getlogin()).encode()
    raw = hashlib.pbkdf2_hmac('sha256', b'aegis-v5-config-key', salt, 200000)
    return base64.urlsafe_b64encode(raw)

def _get_fernet():
    """Get Fernet cipher. Returns None if cryptography not installed."""
    try:
        from cryptography.fernet import Fernet
        return Fernet(_derive_key())
    except ImportError:
        return None

def load_config():
    """Load saved config, decrypting sensitive fields with Fernet."""
    try:
        if not CONFIG_FILE.exists():
            return {}
        data = json.loads(CONFIG_FILE.read_text())
        fernet = _get_fernet()
        for key in ('sudo_pass', 'ssh_pass'):
            if data.get(f'{key}_fernet') and data.get(key):
                if fernet:
                    try:
                        data[key] = fernet.decrypt(data[key].encode()).decode()
                    except:
                        data[key] = ""
                else:
                    data[key] = ""
                data.pop(f'{key}_fernet', None)
            elif data.get(f'{key}_enc') and data.get(key):
                # Legacy v4 base64 — decode (will re-encrypt on next save)
                try:
                    data[key] = base64.b64decode(data[key]).decode()
                except:
                    data[key] = ""
                data.pop(f'{key}_enc', None)
        return data
    except: pass
    return {}

def save_config(data):
    """Save config with Fernet-encrypted passwords. Falls back to omitting passwords."""
    try:
        CONFIG_DIR.mkdir(exist_ok=True)
        safe = dict(data)
        fernet = _get_fernet()
        for key in ('sudo_pass', 'ssh_pass'):
            if safe.get(key):
                if fernet:
                    safe[key] = fernet.encrypt(safe[key].encode()).decode()
                    safe[f'{key}_fernet'] = True
                else:
                    # No cryptography library — don't store passwords at all
                    safe[key] = ""
                safe.pop(f'{key}_enc', None)
        CONFIG_FILE.write_text(json.dumps(safe, indent=2))
        if not IS_WIN:
            os.chmod(str(CONFIG_FILE), 0o600)
    except Exception as e:
        print(f"  Warning: Could not save config: {e}")

def deobfuscate_config(data):
    """Legacy compat — no longer needed, load_config handles all decoding."""
    return data


# ═══════════════════════════════════════════════════
#  CIS BENCHMARK DATA — Kernel, Services, Ports
#  Source: CIS Distribution Independent Linux Benchmark v2.0
#  Source: CIS Ubuntu Linux 22.04 LTS Benchmark v2.0
# ═══════════════════════════════════════════════════

# Chapter 3: Network Configuration — sysctl hardening
# (expected_value, issue_description, cis_control_id, severity)
CIS_SYSCTL_CHECKS = {
    'kernel.randomize_va_space': ('2', 'ASLR not fully enabled. Address Space Layout Randomization makes memory addresses unpredictable, forcing attackers to guess where code lives. Without full ASLR (value=2), buffer overflow and return-oriented programming (ROP) exploits become dramatically easier', 'CIS 1.5.2', 'HIGH'),
    'net.ipv4.tcp_syncookies': ('1', 'SYN flood protection is off. Without SYN cookies, an attacker can exhaust the server connection table by sending thousands of half-open TCP connections (SYN flood), causing legitimate users to be unable to connect — a classic denial-of-service attack', 'CIS 3.3.8', 'HIGH'),
    'net.ipv4.ip_forward': ('0', 'IP forwarding is enabled, meaning this server routes packets between network interfaces like a router. Unless this server is intentionally a router/gateway/VPN, this expands the attack surface and could allow an attacker to pivot between network segments', 'CIS 3.1.1', 'MEDIUM'),
    'net.ipv4.conf.all.accept_redirects': ('0', 'Server accepts ICMP redirect messages, which tell it to change routing. An attacker on the local network can send forged ICMP redirects to reroute your traffic through their machine, enabling man-in-the-middle interception of sensitive data', 'CIS 3.3.2', 'MEDIUM'),
    'net.ipv4.conf.default.accept_redirects': ('0', 'Default setting accepts ICMP redirects — any new network interface will inherit this insecure setting, allowing local network MITM attacks via forged routing updates', 'CIS 3.3.2', 'MEDIUM'),
    'net.ipv4.conf.all.log_martians': ('1', 'Martian packet logging is disabled. Martian packets have impossible source addresses (e.g., 127.0.0.1 arriving from the internet, or private IPs from the wrong interface). These indicate IP spoofing, network reconnaissance, or misconfigured routers. Without logging them, these attacks leave no audit trail', 'CIS 3.3.4', 'MEDIUM'),
    'net.ipv4.conf.default.log_martians': ('1', 'Default does not log martian packets. New network interfaces will silently drop spoofed-source packets with no record, hiding IP spoofing and reconnaissance from security monitoring', 'CIS 3.3.4', 'MEDIUM'),
    'net.ipv4.conf.all.rp_filter': ('1', 'Reverse path filtering is in loose mode (2) or disabled. Strict mode (1) drops incoming packets whose source IP would not be routed back out the same interface — this prevents IP address spoofing. Loose mode (2) only checks if the source IP exists anywhere in the routing table, which is much weaker and allows spoofed packets as long as the forged IP is routable via any interface', 'CIS 3.3.7', 'MEDIUM'),
    'net.ipv4.conf.default.rp_filter': ('1', 'Default reverse path filter is not strict. New interfaces will accept packets with spoofed source addresses, allowing attackers to forge the origin of network traffic and bypass IP-based access controls', 'CIS 3.3.7', 'MEDIUM'),
    'net.ipv4.conf.all.send_redirects': ('0', 'Server is sending ICMP redirect messages, which is only appropriate for routers. An attacker on the same network segment can exploit this to manipulate routing tables of other hosts, redirecting their traffic through the attacker\'s machine for eavesdropping', 'CIS 3.3.1', 'MEDIUM'),
    'net.ipv4.conf.default.send_redirects': ('0', 'Default sends ICMP redirects. New interfaces will behave like routers, potentially allowing attackers to manipulate local network routing for man-in-the-middle attacks', 'CIS 3.3.1', 'MEDIUM'),
    'net.ipv4.conf.all.accept_source_route': ('0', 'Source routing is accepted. This allows the SENDER of a packet to dictate the exact network path it takes, bypassing firewalls and intrusion detection systems. Attackers use source routing to reach internal hosts that should be unreachable from the internet', 'CIS 3.3.3', 'MEDIUM'),
    'net.ipv4.conf.default.accept_source_route': ('0', 'Default accepts source-routed packets. New interfaces will allow attackers to specify custom network paths, bypassing firewall rules and network segmentation', 'CIS 3.3.3', 'MEDIUM'),
    'net.ipv4.conf.all.secure_redirects': ('0', 'Accepts "secure" ICMP redirects (from known gateways). Even these can be spoofed by an attacker who has compromised or is impersonating the default gateway, enabling traffic interception', 'CIS 3.3.5', 'LOW'),
    'net.ipv4.icmp_echo_ignore_broadcasts': ('1', 'Server responds to broadcast ICMP (ping). This enables Smurf amplification attacks where an attacker sends a ping to the broadcast address with your server\'s spoofed source IP, causing every host on the subnet to flood your server with replies', 'CIS 3.3.6', 'MEDIUM'),
    'net.ipv4.icmp_ignore_bogus_error_responses': ('1', 'Server processes bogus ICMP error messages. This fills logs with noise that can mask real attacks and wastes system resources processing invalid network errors', 'CIS 3.3.6', 'LOW'),
    'net.ipv6.conf.all.accept_redirects': ('0', 'Accepts IPv6 ICMP redirects. Same risk as IPv4 redirects — local network attackers can reroute IPv6 traffic through their machine for interception', 'CIS 3.3.2', 'MEDIUM'),
    'net.ipv6.conf.default.accept_redirects': ('0', 'Default accepts IPv6 ICMP redirects on new interfaces, allowing local network attackers to reroute IPv6 traffic through their machine for man-in-the-middle interception', 'CIS 3.3.2', 'MEDIUM'),
    'net.ipv6.conf.all.accept_ra': ('0', 'Accepts IPv6 Router Advertisements. A rogue device on the local network can broadcast itself as an IPv6 router, causing all IPv6 traffic to route through the attacker\'s machine. This is a common and easy-to-execute attack on networks with IPv6 enabled', 'CIS 3.1.2', 'MEDIUM'),
    'net.ipv6.conf.default.accept_ra': ('0', 'Default accepts IPv6 Router Advertisements on new interfaces. Rogue RA attacks can redirect all IPv6 network traffic through an attacker-controlled device', 'CIS 3.1.2', 'MEDIUM'),
    'kernel.sysrq': ('0', 'The Magic SysRq key is enabled. An attacker with physical or console access (including serial console, IPMI, or certain hypervisor consoles) can use keyboard combinations to immediately reboot the server, dump memory contents, kill all processes, or remount filesystems — bypassing all access controls', 'CIS 1.5.3', 'LOW'),
    'fs.suid_dumpable': ('0', 'SUID programs create core dumps when they crash. Core dumps from privileged processes can contain passwords, encryption keys, database credentials, and other sensitive data from memory. An attacker who can trigger a crash and read the resulting dump file can extract these secrets to escalate privileges', 'CIS 1.5.1', 'MEDIUM'),
}

# CIS Chapter 2: Services — organized by category with risk data
CIS_RISKY_SERVICES = {
    # Legacy/insecure protocols (CIS 2.1)
    'telnet': {'sev': 'CRITICAL', 'cis': 'CIS 2.1.1', 'reason': 'Transmits all data including passwords in plaintext — any network observer can capture credentials. Use SSH instead.', 'cat': 'legacy'},
    'rsh': {'sev': 'CRITICAL', 'cis': 'CIS 2.1.2', 'reason': 'Remote shell with no encryption or strong authentication — all commands and output transmitted in cleartext, trivially intercepted', 'cat': 'legacy'},
    'rlogin': {'sev': 'CRITICAL', 'cis': 'CIS 2.1.3', 'reason': 'Remote login protocol with no encryption — credentials and session data sent in cleartext, easily captured on the network', 'cat': 'legacy'},
    'rexec': {'sev': 'CRITICAL', 'cis': 'CIS 2.1.4', 'reason': 'Remote command execution with no encryption or modern authentication — commands and credentials transmitted in cleartext', 'cat': 'legacy'},
    'tftp': {'sev': 'HIGH', 'cis': 'CIS 2.1.5', 'reason': 'Trivial FTP has no authentication mechanism — anyone who can reach the port can read and write files, enabling data theft or malware upload', 'cat': 'legacy'},
    'xinetd': {'sev': 'MEDIUM', 'cis': 'CIS 2.1.7', 'reason': 'Legacy super-server that listens on ports and spawns services on demand — replaced by systemd socket activation, unnecessary attack surface', 'cat': 'legacy'},
    'inetd': {'sev': 'MEDIUM', 'cis': 'CIS 2.1.7', 'reason': 'Legacy super-server that listens on ports and spawns services on demand — replaced by systemd, adds unnecessary listening ports', 'cat': 'legacy'},
    # FTP (CIS 2.2.12)
    'vsftpd': {'sev': 'HIGH', 'cis': 'CIS 2.2.12', 'reason': 'FTP transmits credentials and files in plaintext — use SFTP (SSH File Transfer Protocol) for encrypted file transfers instead', 'cat': 'file_transfer'},
    'proftpd': {'sev': 'HIGH', 'cis': 'CIS 2.2.12', 'reason': 'FTP server transmitting credentials in plaintext. ProFTPD has had multiple critical CVEs. Use SFTP instead.', 'cat': 'file_transfer'},
    'pure-ftpd': {'sev': 'HIGH', 'cis': 'CIS 2.2.12', 'reason': 'FTP server transmitting credentials in plaintext. Replace with SFTP for encrypted, authenticated file transfers.', 'cat': 'file_transfer'},
    # Network services (CIS 2.2)
    'snmpd': {'sev': 'MEDIUM', 'cis': 'CIS 2.2.14', 'reason': 'SNMP v1/v2c uses plaintext community strings as passwords — easily sniffed. Upgrade to SNMPv3 or disable if not used for monitoring.', 'cat': 'network'},
    'rpcbind': {'sev': 'MEDIUM', 'cis': 'CIS 2.2.6', 'reason': 'RPC port mapper exposes internal service locations to the network — commonly exploited for NFS attacks and information gathering', 'cat': 'network'},
    'nfs-server': {'sev': 'MEDIUM', 'cis': 'CIS 2.2.7', 'reason': 'NFS file sharing often misconfigured with world-readable exports. Verify /etc/exports restricts access to specific hosts.', 'cat': 'network'},
    'nfs-kernel-server': {'sev': 'MEDIUM', 'cis': 'CIS 2.2.7', 'reason': 'NFS kernel server — shares filesystems over network, often misconfigured with overly permissive exports allowing unauthorized data access', 'cat': 'network'},
    # Desktop/GUI (CIS 2.2)
    'avahi-daemon': {'sev': 'MEDIUM', 'cis': 'CIS 2.2.3', 'reason': 'mDNS/DNS-SD service discovery broadcasts server presence to the local network — not needed on servers, expands attack surface', 'cat': 'desktop'},
    'cups': {'sev': 'LOW', 'cis': 'CIS 2.2.4', 'reason': 'Print server daemon unnecessary on most servers — exposes port 631 and has had recent remote code execution vulnerabilities', 'cat': 'desktop'},
    'cups-browsed': {'sev': 'LOW', 'cis': 'CIS 2.2.4', 'reason': 'CUPS printer browser daemon — has had severe recent CVEs (CVE-2024-47176) allowing remote code execution via crafted UDP packets', 'cat': 'desktop'},
    'bluetooth': {'sev': 'LOW', 'cis': 'CIS 2.2.18', 'reason': 'Bluetooth protocol stack — servers have no use for Bluetooth, and the stack has a history of vulnerabilities (BlueBorne, BLESA) enabling remote code execution', 'cat': 'desktop'},
    'gdm': {'sev': 'LOW', 'cis': 'CIS 2.2.1', 'reason': 'GNOME Display Manager provides graphical login — servers should be managed via SSH, GUI adds unnecessary packages and attack surface', 'cat': 'desktop'},
    'lightdm': {'sev': 'LOW', 'cis': 'CIS 2.2.1', 'reason': 'GUI login manager unnecessary on servers — adds graphical libraries and dependencies that expand the attack surface significantly', 'cat': 'desktop'},
    'xrdp': {'sev': 'MEDIUM', 'cis': 'N/A', 'reason': 'RDP remote desktop server — heavily targeted by ransomware operators and brute-force bots. Restrict to VPN-only access if needed.', 'cat': 'remote_access'},
    # DNS (CIS 2.2.8)
    'bind9': {'sev': 'MEDIUM', 'cis': 'CIS 2.2.8', 'reason': 'DNS server — ensure this is intentional and properly hardened. DNS is a frequent target for cache poisoning, DDoS amplification, and zone transfer attacks.', 'cat': 'dns'},
    'named': {'sev': 'MEDIUM', 'cis': 'CIS 2.2.8', 'reason': 'BIND DNS server — one of the most frequently exploited network services. Ensure zone transfers are restricted, recursion is disabled for external queries.', 'cat': 'dns'},
    # Proxy (CIS 2.2.11)
    'squid': {'sev': 'MEDIUM', 'cis': 'CIS 2.2.11', 'reason': 'HTTP proxy server — if misconfigured as an open proxy, attackers use it to anonymize malicious traffic through your server\'s IP address', 'cat': 'proxy'},
    # Mail (CIS 2.2.15) — context-dependent
    'postfix': {'sev': 'LOW', 'cis': 'CIS 2.2.15', 'reason': 'Mail Transfer Agent — if not a mail server, disable to prevent open relay abuse where attackers send spam through your server', 'cat': 'mail'},
    'sendmail': {'sev': 'MEDIUM', 'cis': 'CIS 2.2.15', 'reason': 'Legacy Mail Transfer Agent with notoriously complex configuration and long exploit history — if mail is needed, Postfix is safer. Disable if not a mail server.', 'cat': 'mail'},
    'exim4': {'sev': 'LOW', 'cis': 'CIS 2.2.15', 'reason': 'Mail Transfer Agent — if this server is not a mail server, disable to prevent open relay abuse and reduce attack surface', 'cat': 'mail'},
    'dovecot': {'sev': 'LOW', 'cis': 'CIS 2.2.15', 'reason': 'IMAP/POP3 server for mail retrieval — exposes ports 143/993/110/995. Disable if not a mail server to prevent credential probing.', 'cat': 'mail'},
    'courier-imap': {'sev': 'LOW', 'cis': 'CIS 2.2.15', 'reason': 'IMAP server for mail retrieval — exposes network ports for email access. Disable if this is not a mail server.', 'cat': 'mail'},
    # Database — exposure awareness
    'mysql': {'sev': 'LOW', 'cis': 'N/A', 'reason': 'Database server — verify bind-address is set to 127.0.0.1 in my.cnf to prevent external access to database port 3306', 'cat': 'database'},
    'mariadb': {'sev': 'LOW', 'cis': 'N/A', 'reason': 'Database server — verify bind-address restricts to localhost. An exposed database port allows brute-force and SQL injection attacks.', 'cat': 'database'},
    'mongod': {'sev': 'MEDIUM', 'cis': 'N/A', 'reason': 'MongoDB — historically defaults to no authentication and binds to all interfaces. Thousands of exposed MongoDB instances have been ransomed. Verify auth is enabled and bind to localhost.', 'cat': 'database'},
    'redis-server': {'sev': 'MEDIUM', 'cis': 'N/A', 'reason': 'Redis — defaults to no authentication and no encryption. Exposed Redis instances can be exploited to write SSH keys, crontabs, or webshells to disk. Bind to localhost and set requirepass.', 'cat': 'database'},
    'memcached': {'sev': 'MEDIUM', 'cis': 'N/A', 'reason': 'Memcached has no built-in authentication — exposed instances are exploited for massive DDoS amplification attacks (1.7 Tbps record) and data theft', 'cat': 'database'},
    'elasticsearch': {'sev': 'MEDIUM', 'cis': 'N/A', 'reason': 'Elasticsearch — ensure X-Pack security or OpenSearch security plugin is enabled. Unsecured instances expose all indexed data to anyone.', 'cat': 'database'},
}

# Server role profiles — expected ports and services per role
SERVER_ROLES = {
    'general': {'label': 'General Purpose', 'expected_ports': {'22'}, 'expected_services': set(),
                'desc': 'Baseline — only SSH expected'},
    'web': {'label': 'Web Server', 'expected_ports': {'22', '80', '443'}, 'expected_services': {'nginx', 'apache2', 'httpd'},
            'desc': 'SSH + HTTP/HTTPS expected'},
    'database': {'label': 'Database Server', 'expected_ports': {'22', '5432', '3306', '27017'},
                 'expected_services': {'postgresql', 'mysql', 'mariadb', 'mongod'}, 'desc': 'SSH + DB ports'},
    'mail': {'label': 'Mail Server', 'expected_ports': {'22', '25', '80', '443', '143', '587', '993', '995', '110'},
             'expected_services': {'postfix', 'sendmail', 'exim4', 'dovecot', 'courier-imap'}, 'desc': 'SMTP/IMAP/POP3'},
    'web+db': {'label': 'Web + Database', 'expected_ports': {'22', '80', '443', '5432', '3306'},
               'expected_services': {'nginx', 'apache2', 'httpd', 'postgresql', 'mysql', 'mariadb'}, 'desc': 'HTTP + DB'},
    'bastion': {'label': 'Bastion Host', 'expected_ports': {'22'}, 'expected_services': set(),
                'desc': 'Only SSH, minimal services'},
}

# Dangerous external ports
DANGEROUS_EXT_PORTS = {
    21: ('FTP', 'HIGH'), 23: ('Telnet', 'CRITICAL'), 25: ('SMTP', 'MEDIUM'),
    110: ('POP3', 'HIGH'), 111: ('RPC', 'HIGH'), 135: ('MS-RPC', 'HIGH'),
    139: ('NetBIOS', 'HIGH'), 445: ('SMB', 'CRITICAL'), 1433: ('MSSQL', 'HIGH'),
    3306: ('MySQL', 'HIGH'), 3389: ('RDP', 'HIGH'), 5432: ('PostgreSQL', 'HIGH'),
    5900: ('VNC', 'CRITICAL'), 6379: ('Redis', 'CRITICAL'), 9200: ('Elasticsearch', 'HIGH'),
    11211: ('Memcached', 'CRITICAL'), 27017: ('MongoDB', 'HIGH'),
}


# ═══════════════════════════════════════════════════
#  SSH ENGINE
# ═══════════════════════════════════════════════════
class SSH:
    def __init__(self, host, user, key_file=None, sudo_pass=None, ssh_pass=None):
        self.host = host
        self.user = user
        self.key_file = key_file
        self.sudo_pass = sudo_pass
        self.ssh_pass = ssh_pass
        self._sudo_mode = None
        self._debug_lines = []
        self._control_path = None
        self._control_proc = None

        if not self.key_file and not self.ssh_pass:
            self.key_file = self._find_ssh_key()

        # Setup ControlMaster socket path
        self._setup_control_path()

    def _setup_control_path(self):
        """Create a unique socket path for SSH multiplexing."""
        # Windows OpenSSH doesn't support Unix domain sockets for ControlMaster
        if IS_WIN:
            self._control_path = None
            return
        import tempfile
        d = tempfile.mkdtemp(prefix='aegis_ssh_')
        self._control_path = os.path.join(d, 'ctrl-%r@%h:%p')
        self._debug(f"ControlMaster path: {d}")

    def _start_control_master(self):
        """Start a persistent SSH ControlMaster connection."""
        if not self._control_path:
            return False
        self._stop_control_master()
        cmd = self._ssh_base_raw() + [
            "-o", f"ControlPath={self._control_path}",
            "-o", "ControlMaster=yes",
            "-o", "ControlPersist=300",
            "-N",
        ]
        try:
            kwargs = {}
            if IS_WIN:
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            self._control_proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kwargs)
            _track_subprocess(self._control_proc)
            # Wait for master to establish, then verify with a quick command
            import time
            for i in range(60):  # Up to 6 seconds
                time.sleep(0.1)
                if self._control_proc.poll() is not None:
                    out = self._control_proc.stderr.read()
                    self._debug(f"ControlMaster exited early: {out.strip()[:100]}")
                    self._control_proc = None
                    return False
                # After 1 second, try a quick check command via the master
                if i == 10 or i == 30 or i == 50:
                    check = subprocess.run(
                        self._ssh_base_raw() + [
                            "-o", f"ControlPath={self._control_path}",
                            "-o", "ControlMaster=no",
                            "echo CM_OK"],
                        capture_output=True, text=True, timeout=5,
                        **({"creationflags": subprocess.CREATE_NO_WINDOW} if IS_WIN else {}))
                    if "CM_OK" in check.stdout:
                        self._debug("ControlMaster active — all commands will reuse this connection")
                        return True
            self._debug("ControlMaster: could not verify — falling back to direct connections")
            self._stop_control_master()
            return False
        except Exception as e:
            self._debug(f"ControlMaster error: {e} — using direct connections")
            self._control_proc = None
            return False

    def _stop_control_master(self):
        """Tear down the persistent connection."""
        if self._control_proc:
            try:
                self._control_proc.terminate()
                self._control_proc.wait(timeout=3)
            except:
                try: self._control_proc.kill()
                except: pass
            _untrack_subprocess(self._control_proc)
            self._control_proc = None
        # Also send exit command via socket
        if self._control_path:
            try:
                subprocess.run(
                    ["ssh", "-o", f"ControlPath={self._control_path}", "-O", "exit",
                     f"{self.user}@{self.host}"],
                    capture_output=True, timeout=3)
            except: pass
            # Clean up socket directory
            expanded = self._control_path.replace('%r', self.user).replace('%h', self.host).replace('%p', '22')
            sock_dir = os.path.dirname(self._control_path)
            try:
                import shutil
                shutil.rmtree(sock_dir, ignore_errors=True)
            except: pass

    def cleanup(self):
        """Full cleanup — call on shutdown."""
        self._stop_control_master()

    def _find_ssh_key(self):
        home = os.environ.get('USERPROFILE', '') if IS_WIN else str(Path.home())
        for name in ['id_ed25519', 'id_rsa', 'id_ecdsa']:
            k = os.path.join(home, '.ssh', name)
            if os.path.isfile(k):
                self._debug(f"Found key: {k}")
                return k
        return None

    def _debug(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self._debug_lines.append(msg)
        try:
            print(f"  [{ts}] [SSH] {msg}", flush=True)
        except (ValueError, OSError):
            pass  # stdout closed during shutdown

    def _ssh_base_raw(self):
        """Base SSH args WITHOUT ControlPath — used to establish master."""
        cmd = ["ssh", "-T",
               "-o", "StrictHostKeyChecking=no",
               "-o", "UserKnownHostsFile=/dev/null" if not IS_WIN else "UserKnownHostsFile=NUL",
               "-o", "ConnectTimeout=20",
               "-o", "ServerAliveInterval=5",
               "-o", "ServerAliveCountMax=3",
               "-o", "IdentitiesOnly=yes",
               ]
        if self.ssh_pass:
            cmd += ["-o", "BatchMode=no"]
        else:
            cmd += ["-o", "BatchMode=yes",
                    "-o", "PreferredAuthentications=publickey"]
        if self.key_file:
            cmd += ["-i", self.key_file]
        cmd += [f"{self.user}@{self.host}"]
        return cmd

    def _ssh_base(self):
        """SSH args with ControlPath for connection reuse."""
        cmd = self._ssh_base_raw()
        if self._control_path and self._control_proc and self._control_proc.poll() is None:
            # Insert ControlPath before the user@host (last element)
            target = cmd.pop()
            cmd += ["-o", f"ControlPath={self._control_path}",
                    "-o", "ControlMaster=no"]
            cmd.append(target)
        return cmd

    def run(self, cmd, timeout=90):
        ssh_cmd = self._ssh_base() + [cmd]
        try:
            kwargs = {}
            if IS_WIN:
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            proc = subprocess.Popen(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kwargs)
            _track_subprocess(proc)
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
                result = stdout + stderr
                code = proc.returncode
                # If we used ControlMaster and got instant failure, retry without it
                if code != 0 and self._control_proc and ('mux' in result.lower() or
                    'control' in result.lower() or 'connection refused' in result.lower()
                    or (result.strip() == '' and code == 255)):
                    self._debug("ControlMaster connection failed — retrying direct...")
                    self._stop_control_master()
                    ssh_cmd2 = self._ssh_base() + [cmd]
                    proc2 = subprocess.Popen(ssh_cmd2, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kwargs)
                    _track_subprocess(proc2)
                    try:
                        stdout2, stderr2 = proc2.communicate(timeout=timeout)
                        return stdout2 + stderr2, proc2.returncode
                    except subprocess.TimeoutExpired:
                        proc2.kill(); proc2.wait()
                        return "[TIMEOUT]", 1
                    finally:
                        _untrack_subprocess(proc2)
                return result, code
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                return "[TIMEOUT]", 1
            finally:
                _untrack_subprocess(proc)
        except Exception as e: return f"[ERROR] {e}", 1

    def sudo(self, cmd, timeout=90):
        # Wrap multi-line or chained commands so sudo applies to ALL of them
        if '\n' in cmd or '&&' in cmd or '|' in cmd:
            import base64
            encoded = base64.b64encode(cmd.encode()).decode()
            wrapped = f"bash -c \"$(echo '{encoded}' | base64 -d)\""
        else:
            wrapped = cmd

        if self._sudo_mode == 'nopasswd':
            return self.run(f"sudo -n {wrapped}", timeout=timeout)
        if self._sudo_mode == 'password' and self.sudo_pass:
            escaped = self.sudo_pass.replace("'", "'\\''")
            out, code = self.run(f"echo '{escaped}' | sudo -S {wrapped} 2>&1", timeout=timeout)
            out = re.sub(r'\[sudo\] password for \w+:\s*', '', out)
            return out, code
        if self._sudo_mode is None:
            if self.sudo_pass:
                escaped = self.sudo_pass.replace("'", "'\\''")
                out, code = self.run(f"echo '{escaped}' | sudo -S {wrapped} 2>&1", timeout=timeout)
                out = re.sub(r'\[sudo\] password for \w+:\s*', '', out)
                if "incorrect password" in out.lower() or "sorry" in out.lower():
                    self._debug("sudo: WRONG PASSWORD")
                else:
                    self._sudo_mode = 'password'
                    self._debug("sudo: password")
                    return out, code
            else:
                out, code = self.run(f"sudo -n {wrapped} 2>&1", timeout=8)
                if code == 0 and "password is required" not in out.lower():
                    self._sudo_mode = 'nopasswd'
                    self._debug("sudo: nopasswd")
                    return out, code
        # Fallback: still run with sudo if we have a password, just don't cache the mode
        if self.sudo_pass:
            escaped = self.sudo_pass.replace("'", "'\\''")
            out, code = self.run(f"echo '{escaped}' | sudo -S {wrapped} 2>&1", timeout=timeout)
            out = re.sub(r'\[sudo\] password for \w+:\s*', '', out)
            return out, code
        return self.run(cmd, timeout=timeout)

    def test(self):
        auth = f"key={self.key_file}" if self.key_file else "password" if self.ssh_pass else "default"
        self._debug(f"Connecting to {self.user}@{self.host} ({auth})...")
        for attempt, tout in [(1, 30), (2, 45)]:
            # First attempt uses -v for diagnostics
            if attempt == 1:
                out, code = self._run_verbose("echo AEGIS_OK && hostname && echo AEGIS_END", timeout=tout)
            else:
                out, code = self.run("echo AEGIS_OK && hostname && echo AEGIS_END", timeout=tout)
            if "AEGIS_OK" in out:
                try:
                    after_ok = out.split("AEGIS_OK")[1]
                    before_end = after_ok.split("AEGIS_END")[0] if "AEGIS_END" in after_ok else after_ok
                    hostname = before_end.strip().split('\n')[0].strip() or "unknown"
                except:
                    hostname = "unknown"
                self._debug(f"Connected! Host: {hostname}")
                # Establish persistent multiplexed connection for speed (non-Windows)
                if self._control_path and not self._control_proc:
                    self._start_control_master()
                return True, hostname
            if attempt == 1 and "[TIMEOUT]" in out:
                self._debug("Timeout on attempt 1, retrying...")
                continue
            break
        self._debug(f"FAILED: {out.strip()[:150]}")
        return False, None

    def _run_verbose(self, cmd, timeout=30):
        """Run SSH with -v to capture connection diagnostics."""
        ssh_cmd = self._ssh_base() + [cmd]
        # Insert -v after 'ssh' (or after '-T' if present)
        for i, arg in enumerate(ssh_cmd):
            if arg == 'ssh' or (i == 0 and 'ssh' in arg):
                ssh_cmd.insert(i + 1, '-v')
                break
        try:
            kwargs = {}
            if IS_WIN:
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            proc = subprocess.Popen(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kwargs)
            _track_subprocess(proc)
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
                # Log key diagnostic lines
                for line in stderr.split('\n'):
                    ls = line.strip()
                    if any(k in ls.lower() for k in ['authenticat', 'connection established',
                            'identity file', 'offering', 'server accepts', 'pledge',
                            'sending env', 'accepted key', 'session opened']):
                        self._debug(f"[v] {ls[:140]}")
                return stdout + stderr, proc.returncode
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    _, partial = proc.communicate(timeout=2)
                    lines = [l.strip() for l in partial.split('\n') if l.strip() and l.startswith('debug1:')]
                    if lines:
                        self._debug(f"[v] Last before timeout: {lines[-1][:140]}")
                except: pass
                proc.wait()
                return "[TIMEOUT]", 1
            finally:
                _untrack_subprocess(proc)
        except Exception as e: return f"[ERROR] {e}", 1

    def test_sudo(self):
        out, code = self.sudo("echo SUDO_OK", timeout=20)
        ok = "SUDO_OK" in out
        self._debug(f"Sudo: {'OK' if ok else 'FAILED'} (mode: {self._sudo_mode})")
        return ok


# ═══════════════════════════════════════════════════
#  SCAN ENGINE
# ═══════════════════════════════════════════════════

def _strip_sudo(cmd):
    """Strip 'sudo' prefixes from fix commands since SSH.sudo() already adds sudo.
    Handles: 'sudo cmd', chained 'sudo X && sudo Y', 'sudo X; sudo Y'.
    Also prepends DEBIAN_FRONTEND=noninteractive for apt/dpkg commands."""
    def strip_one(c):
        c = c.strip()
        if c.startswith('sudo '):
            c = c[5:].lstrip()
            # Strip sudo flags like -S, -E etc
            while c and c[0] == '-' and len(c) > 1 and c[1] != '-' and ' ' in c:
                c = c[c.index(' ')+1:].lstrip()
        return c
    # Split on && and ; to strip sudo from each segment
    # First split on &&, then each piece on ;
    if '&&' in cmd or ';' in cmd:
        # Use regex to split on && or ; while preserving the separator
        parts = re.split(r'(&&|;)', cmd)
        result = []
        for part in parts:
            if part.strip() in ('&&', ';'):
                result.append(part)
            else:
                result.append(strip_one(part))
        cmd = ''.join(result)
    else:
        cmd = strip_one(cmd)
    # Ensure apt/dpkg run non-interactively
    if any(k in cmd for k in ('apt ', 'apt-get ', 'dpkg-reconfigure')):
        cmd = f"env DEBIAN_FRONTEND=noninteractive {cmd}"
    return cmd

class ScanState:
    def __init__(self):
        self.data = {}
        self.findings = []
        self.actions = []
        self.log_lines = []
        self.scanning = False
        self.progress = 0
        self.current_module = ""
        self.connected = False
        self.error = None
        self.server_role = 'general'
        self.custom_expected_ports = set()
        self.custom_expected_services = set()
        self.sudo_available = False
        self.sudo_sections_skipped = []
        self.scan_timestamp = None
        self.previous_scan = None

    def add_finding(self, sev, title, detail, fix_cmd=None, undo_cmd=None, cis_ref=None):
        for f in self.findings:
            if f['title'] == title: return f
        f = {"id": len(self.findings)+1, "sev": sev, "title": title, "detail": detail,
             "fix_cmd": fix_cmd, "undo_cmd": undo_cmd, "fixed": False, "cis_ref": cis_ref}
        self.findings.append(f)
        return f

    def add_action(self, desc, cmd, undo_cmd=None):
        self.actions.append({"id": len(self.actions)+1, "desc": desc, "cmd": cmd,
            "undo_cmd": undo_cmd, "ts": datetime.now().strftime("%H:%M:%S"), "undone": False})

    @property
    def score(self):
        d = 0
        for f in self.findings:
            if f.get('fixed'): continue
            w = {"CRITICAL": 20, "HIGH": 12, "MEDIUM": 5, "LOW": 2}.get(f['sev'], 0)
            d += w
        # Penalty for sections that couldn't be scanned
        if self.sudo_sections_skipped:
            d += len(self.sudo_sections_skipped) * 3
        return max(0, 100 - d)

    def log(self, msg):
        self.log_lines.append({"ts": datetime.now().strftime("%H:%M:%S"), "msg": msg})
        print(f"  [{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)

    def _compute_diff(self):
        if not self.previous_scan:
            return None
        prev = self.previous_scan
        diff = {"new_findings": [], "resolved_findings": [], "score_change": 0}
        prev_titles = {f['title'] for f in prev.get('findings', []) if not f.get('fixed')}
        curr_titles = {f['title'] for f in self.findings if not f.get('fixed')}
        diff['new_findings'] = sorted(curr_titles - prev_titles)
        diff['resolved_findings'] = sorted(prev_titles - curr_titles)
        diff['score_change'] = self.score - prev.get('score', 0)
        return diff

    def to_dict(self):
        return {
            "score": self.score, "findings": self.findings, "actions": self.actions,
            "data": self.data, "scanning": self.scanning, "progress": self.progress,
            "current_module": self.current_module, "log": self.log_lines[-80:],
            "connected": self.connected, "error": self.error,
            "server_role": self.server_role,
            "custom_expected_ports": sorted(self.custom_expected_ports),
            "custom_expected_services": sorted(self.custom_expected_services),
            "sudo_available": self.sudo_available,
            "sudo_sections_skipped": self.sudo_sections_skipped,
            "scan_timestamp": self.scan_timestamp,
            "scan_diff": self._compute_diff(),
        }

STATE = ScanState()
SSH_CONN = None


def section(output, name):
    """Extract a named section from delimited output."""
    m = re.search(rf'==={name}===\n(.*?)(?====\w+===|\Z)', output, re.DOTALL)
    return m.group(1).strip() if m else ""


def _save_scan_history(state):
    """Save scan results for diff comparison."""
    try:
        HISTORY_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        summary = {"timestamp": ts, "score": state.score,
            "findings": [{"sev": f['sev'], "title": f['title'], "fixed": f.get('fixed', False)} for f in state.findings],
            "server_role": state.server_role, "hostname": state.data.get('hostname', '?')}
        (HISTORY_DIR / f"scan_{ts}.json").write_text(json.dumps(summary, indent=2))
        for old in sorted(HISTORY_DIR.glob("scan_*.json"), reverse=True)[50:]:
            old.unlink()
    except: pass

def _load_previous_scan():
    try:
        scans = sorted(HISTORY_DIR.glob("scan_*.json"), reverse=True)
        if scans: return json.loads(scans[0].read_text())
    except: pass
    return None


_scan_lock = threading.Lock()
_scan_id = 0

def run_full_scan(ssh, state):
    global _scan_id
    with _scan_lock:
        _scan_id += 1
        my_id = _scan_id
    state.scanning = True
    state.findings = []
    state.actions = []
    state.data = {}
    state.log_lines = []
    state.progress = 0
    state.error = None
    state.sudo_sections_skipped = []
    state.scan_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    state.previous_scan = _load_previous_scan()

    try:
        # Check we're still the current scan (abort if superseded)
        if _scan_id != my_id:
            return
        _run_full_scan_inner(ssh, state)
    except Exception as e:
        state.log(f"✗ Scan error: {e}")
        state.error = str(e)
        import traceback; traceback.print_exc()
    finally:
        state.scanning = False
        state.progress = 100
        state.current_module = "Complete"


def _run_full_scan_inner(ssh, state):

    # Flush SSH debug (atomic swap to prevent double-flush)
    lines, ssh._debug_lines = ssh._debug_lines, []
    for line in lines:
        state.log(f"[SSH] {line}")

    # ── Phase 1: Connect ──
    state.current_module = "Connecting"
    state.progress = 5
    state.log("▶ Connecting...")

    ok, hostname = ssh.test()
    lines, ssh._debug_lines = ssh._debug_lines, []
    seen = set()
    for line in lines:
        if line not in seen:
            seen.add(line)
            state.log(f"[SSH] {line}")

    state.data['hostname'] = hostname or "?"
    state.data['connected'] = ok
    state.connected = ok
    if not ok:
        state.log("✗ Connection failed")
        state.error = "SSH connection failed"
        return

    state.log(f"✓ Connected to {hostname}")
    has_sudo = ssh.test_sudo()
    lines, ssh._debug_lines = ssh._debug_lines, []
    seen2 = set()
    for line in lines:
        if line not in seen2:
            seen2.add(line)
            state.log(f"[SSH] {line}")
    state.data['has_sudo'] = has_sudo
    state.data['sudo_mode'] = ssh._sudo_mode or 'none'
    state.sudo_available = has_sudo
    state.progress = 10

    # ── Phase 2: Non-sudo batch ──
    state.current_module = "System & Users"
    state.log("▶ Gathering system info...")
    state.progress = 15

    nosudo_script = r"""
echo '===SYSTEM==='
cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2
uname -r
uptime -p 2>/dev/null
free -h 2>/dev/null | grep Mem | awk '{print $3"/"$2}'
df -h / 2>/dev/null | tail -1 | awk '{print $3"/"$2" ("$5")"}'
nproc 2>/dev/null
echo '===USERS==='
grep -vE '(nologin|false|sync|halt|shutdown)' /etc/passwd
echo '===UID0==='
awk -F: '$3==0{print $1}' /etc/passwd
echo '===SUDOGRP==='
getent group sudo 2>/dev/null
echo '===LAST==='
last -n 15 -i 2>/dev/null || last -n 15 2>/dev/null
echo '===KEYS==='
for d in /root /home/*; do if [ -f "$d/.ssh/authorized_keys" ]; then echo "FOUND:$d/.ssh/authorized_keys $(wc -l < "$d/.ssh/authorized_keys")"; fi; done
echo '===UPDATES==='
apt list --upgradable 2>/dev/null
echo '===AUTOUPD==='
dpkg -l unattended-upgrades 2>/dev/null | grep '^ii'
echo '===NGINX==='
cat /etc/nginx/sites-enabled/* 2>/dev/null
cat /etc/nginx/snippets/security-headers.conf 2>/dev/null
echo '===GUNICORN==='
pgrep -a gunicorn 2>/dev/null
echo '===XRDPPKG==='
dpkg -l xrdp 2>/dev/null | grep '^ii'
echo '===CRONTAB==='
crontab -l 2>/dev/null
echo '===DONE==='
"""
    nosudo_out, _ = ssh.run(nosudo_script.strip())
    state.progress = 30

    # Parse system
    sys_lines = section(nosudo_out, 'SYSTEM').split('\n')
    state.data['system'] = {
        "os": sys_lines[0] if len(sys_lines) > 0 else "?",
        "kernel": sys_lines[1] if len(sys_lines) > 1 else "?",
        "uptime": sys_lines[2].replace("up ", "") if len(sys_lines) > 2 else "?",
        "memory": sys_lines[3] if len(sys_lines) > 3 else "?",
        "disk": sys_lines[4] if len(sys_lines) > 4 else "?",
        "cpus": sys_lines[5] if len(sys_lines) > 5 else "?",
    }
    state.log(f"✓ System: {state.data['system']['os']}")

    # Parse users
    users = []
    for line in section(nosudo_out, 'USERS').split('\n'):
        if ':' in line:
            p = line.split(':')
            users.append({"name": p[0], "uid": p[2], "home": p[5] if len(p) > 5 else "", "shell": p[6] if len(p) > 6 else ""})
    uid0_out = section(nosudo_out, 'UID0')
    uid0_count = len([u for u in uid0_out.split('\n') if u.strip()])
    if uid0_count > 1:
        state.add_finding("HIGH", f"Multiple UID 0 accounts ({uid0_count})",
            f"{uid0_count} accounts have UID 0 (root-level). Only the 'root' account should have UID 0. "
            "Additional UID 0 accounts may have been created by an attacker to maintain persistent root access. "
            "Each one has full system control and can read/modify any file, install backdoors, or wipe logs.",
            cis_ref="CIS 6.2.2")
    state.data['users'] = {"accounts": users, "uid0_count": uid0_count,
        "sudo_group": section(nosudo_out, 'SUDOGRP'),
        "last_logins": [l.strip() for l in section(nosudo_out, 'LAST').split('\n') if l.strip()][:15]}

    # SSH keys — check all users
    key_out = section(nosudo_out, 'KEYS')
    has_keys = "FOUND:" in key_out
    key_count = 0
    key_users = []
    for line in key_out.split('\n'):
        m = re.match(r'FOUND:(\S+)\s+(\d+)', line)
        if m:
            key_users.append({"path": m.group(1), "count": int(m.group(2))})
            key_count += int(m.group(2))
    if not has_keys:
        state.add_finding("HIGH", "No SSH keys configured",
            "No authorized_keys files found for any user account. Without SSH key authentication, the server relies "
            "solely on passwords, which are vulnerable to brute force attacks. SSH keys use 2048+ bit cryptographic "
            "keys that are practically impossible to guess. Configure SSH keys and then disable PasswordAuthentication.")

    # Updates
    upd_out = section(nosudo_out, 'UPDATES')
    pkgs = []
    for line in upd_out.split('\n'):
        if '/' in line and 'Listing' not in line:
            pkgs.append({"name": line.split('/')[0], "security": 'security' in line.lower()})
    auto_updates = 'unattended-upgrades' in section(nosudo_out, 'AUTOUPD')
    sec_count = len([p for p in pkgs if p['security']])
    if pkgs:
        state.add_finding("HIGH" if sec_count else "MEDIUM", f"{len(pkgs)} pending updates ({sec_count} security)",
            f"{len(pkgs)} packages have available updates, including {sec_count} security patches. "
            "Unpatched software is the #1 vector for server compromises — known vulnerabilities have public exploits "
            "that attackers scan for automatically. Security updates fix actively exploited bugs in the kernel, "
            "OpenSSL, SSH, and other critical services. Apply updates promptly.",
            "sudo apt-get update && sudo apt-get dist-upgrade -y", cis_ref="CIS 1.9")
    if not auto_updates:
        state.add_finding("MEDIUM", "No automatic security updates",
            "The unattended-upgrades package is not installed. Without automatic updates, security patches must be "
            "applied manually. Critical vulnerabilities like Log4Shell, Heartbleed, and kernel exploits are often "
            "weaponized within hours of disclosure — automatic updates ensure patches are applied even when admins "
            "aren't immediately available.",
            "sudo apt-get update; sudo apt-get install unattended-upgrades -y && sudo dpkg-reconfigure -plow unattended-upgrades",
            cis_ref="CIS 1.9")
    state.data['updates'] = {"packages": pkgs, "auto_updates": auto_updates}

    # Nginx headers — only check if nginx config exists
    nginx_out = section(nosudo_out, 'NGINX')
    sec_headers = ['X-Frame-Options', 'X-Content-Type-Options', 'Content-Security-Policy', 'Strict-Transport-Security']
    missing_headers = [h for h in sec_headers if h.lower() not in nginx_out.lower()] if nginx_out.strip() else []

    # Check if CSP exists but is overly restrictive (missing https: sources which breaks CDN resources)
    csp_needs_update = False
    if nginx_out.strip() and 'content-security-policy' in nginx_out.lower() and 'Content-Security-Policy' not in missing_headers:
        # Check if the CSP allows https: sources — if not, it will break CDN-loaded CSS/JS
        csp_line = ''
        for line in nginx_out.split('\n'):
            if 'content-security-policy' in line.lower():
                csp_line = line
                break
        if csp_line and "https:" not in csp_line:
            csp_needs_update = True

    # Gunicorn
    g_out = section(nosudo_out, 'GUNICORN')
    gw = len(g_out.strip().split('\n')) if g_out.strip() else 0

    # xRDP
    xrdp_installed = 'xrdp' in section(nosudo_out, 'XRDPPKG')

    # User crontab
    user_cron = section(nosudo_out, 'CRONTAB')

    state.log(f"✓ Users: {len(users)} | Updates: {len(pkgs)} pending")
    state.progress = 40

    # ── Phase 3: Sudo batch — comprehensive ──
    sudo_sections = ['Firewall', 'Ports', 'SSH Config', 'Auth Logs', 'File Permissions',
                     'Application Security', 'Process Analysis', 'Service Audit',
                     'Network Connections', 'Kernel Hardening', 'Filesystem', 'Docker',
                     'Cron Jobs', 'Password Policy', 'DNS', 'Audit System']

    if not has_sudo:
        state.log("✗ No sudo — privileged scans CANNOT run")
        state.log("  ╔═══════════════════════════════════════════════════╗")
        state.log("  ║  Provide sudo password to unlock full scanning:  ║")
        state.log("  ║  • Firewall, Ports, SSH config, Kernel hardening ║")
        state.log("  ║  • File permissions, Services, Process analysis  ║")
        state.log("  ║  • Auth logs, Docker, Cron, Password policy, DNS ║")
        state.log("  ╚═══════════════════════════════════════════════════╝")
        state.add_finding("HIGH", "Sudo access not available — scan incomplete",
            f"{len(sudo_sections)} security sections could not be scanned. "
            "Provide sudo password on the login page and rescan.",
            cis_ref="N/A")
        state.sudo_sections_skipped = sudo_sections
        _set_empty_sudo_data(state, has_keys, key_count, missing_headers, gw, xrdp_installed)
    else:
        state.current_module = "Security Scan"
        state.log("▶ Running privileged security scan...")
        state.progress = 45

        sudo_script = r"""
echo '===UFW==='
ufw status verbose 2>/dev/null
echo '===PORTS==='
ss -tlnp 2>/dev/null
echo '===UDPPORTS==='
ss -ulnp 2>/dev/null
echo '===LSOF==='
lsof -i -P -n 2>/dev/null | grep -E '(LISTEN|UDP)' | awk '{print $1, $9}'
echo '===SSHD==='
cat /etc/ssh/sshd_config 2>/dev/null
echo '===F2B==='
fail2ban-client status sshd 2>/dev/null || echo 'F2B_INACTIVE'
echo '===F2BCONF==='
fail2ban-client get sshd bantime 2>/dev/null; echo '---'; fail2ban-client get sshd maxretry 2>/dev/null; echo '---'; fail2ban-client get sshd findtime 2>/dev/null; echo '---'; cat /etc/fail2ban/jail.local 2>/dev/null; echo '---'; cat /etc/fail2ban/jail.d/*.conf 2>/dev/null
echo '===AUTHFAIL==='
grep 'sshd.*Failed password' /var/log/auth.log 2>/dev/null | sed -n 's/.*from \([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\).*/\1/p' | sort | uniq -c | sort -rn | head -20
echo '===FAIL24==='
journalctl -u ssh --since '24 hours ago' --no-pager 2>/dev/null | grep -ci 'failed' || echo '0'
echo '===ACCEPTED==='
grep 'Accepted' /var/log/auth.log 2>/dev/null | tail -10
echo '===SUID==='
find / -xdev -perm -4000 -type f 2>/dev/null
echo '===ENVFILES==='
find / -name '.env' -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | while read f; do echo "$f $(stat -c '%a' "$f" 2>/dev/null)"; done
echo '===SSL==='
find /etc/ssl /etc/letsencrypt /etc/nginx -name '*.pem' -o -name '*.crt' 2>/dev/null | head -10 | while read c; do echo "=CERT= $c"; openssl x509 -in "$c" -noout -subject -dates 2>/dev/null; done
echo '===PGHBA==='
cat /etc/postgresql/*/main/pg_hba.conf 2>/dev/null | grep -vE '^(#|$)'
echo '===PGLISTEN==='
grep -E '^\s*listen_addresses' /etc/postgresql/*/main/postgresql.conf 2>/dev/null || echo 'localhost'
echo '===XRDP==='
systemctl is-active xrdp 2>/dev/null
echo '===XRDPFW==='
ufw status 2>/dev/null | grep 3389
echo '===TOOLS==='
for t in fail2ban ufw apparmor auditd aide rkhunter clamav lynis unattended-upgrades; do command -v $t &>/dev/null && echo "$t:YES" || echo "$t:NO"; done
echo '===PROCS==='
ps aux --sort=-%mem 2>/dev/null | head -30
echo '===SERVICES==='
systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null | grep enabled
echo '===NETCONN==='
ss -tunp 2>/dev/null | grep ESTAB
echo '===SYSCTL==='
sysctl -a 2>/dev/null | grep -E '(randomize_va_space|tcp_syncookies|ip_forward|accept_redirects|log_martians|rp_filter|send_redirects|accept_source_route|secure_redirects|icmp_echo_ignore_broadcasts|icmp_ignore_bogus_error_responses|accept_ra|kernel.sysrq|fs.suid_dumpable)'
echo '===WORLDWRITE==='
find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | head -20
echo '===DOCKER==='
docker ps --format '{{.Names}} {{.Image}} {{.Status}} {{.Ports}}' 2>/dev/null || echo 'DOCKER_NONE'
echo '===CRONTABS==='
cat /etc/crontab 2>/dev/null; echo '---CRONDIR---'; ls /etc/cron.d/ 2>/dev/null; for u in $(cut -f1 -d: /etc/passwd); do c=$(crontab -u "$u" -l 2>/dev/null); if [ -n "$c" ]; then echo "---USER:$u---"; echo "$c"; fi; done
echo '===TMPSTICKY==='
stat -c '%a %n' /tmp /var/tmp 2>/dev/null
echo '===COREDUMP==='
cat /proc/sys/kernel/core_pattern 2>/dev/null
echo '===SWAPENC==='
swapon --show 2>/dev/null
cat /etc/crypttab 2>/dev/null | grep swap
echo '===KMODULES==='
lsmod 2>/dev/null | head -30
echo '===OPENPORTS==='
ss -tlnp 2>/dev/null | awk 'NR>1{print $4}' | grep -v '127.0.0' | grep -v '::1'
echo '===PASSWD_POLICY==='
cat /etc/login.defs 2>/dev/null | grep -E '(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE|LOGIN_RETRIES|ENCRYPT_METHOD)'
echo '===DNS==='
cat /etc/resolv.conf 2>/dev/null
echo '===AUDITD==='
auditctl -l 2>/dev/null || echo 'AUDITD_INACTIVE'
echo '===APPARMOR==='
aa-status 2>/dev/null || apparmor_status 2>/dev/null || echo 'APPARMOR_INACTIVE'
echo '===SUDOERS==='
cat /etc/sudoers 2>/dev/null | grep -vE '^(#|$|Defaults)' ; ls /etc/sudoers.d/ 2>/dev/null
echo '===DONE==='
"""
        sudo_out, _ = ssh.sudo(sudo_script.strip(), timeout=300)
        state.progress = 75

        # Debug: log raw section extraction
        for sname in ['UFW', 'F2B', 'F2BCONF', 'SSHD', 'AUTHFAIL']:
            raw = section(sudo_out, sname)
            state.log(f"  [DBG] {sname}: {len(raw)} chars | {raw[:80].replace(chr(10),' ')}{'...' if len(raw)>80 else ''}")

        # Check if sudo output contains section markers at all
        marker_count = sudo_out.count('===')
        state.log(f"  [DBG] Total sudo output: {len(sudo_out)} chars, {marker_count} markers")

        # Parse ALL sections
        if state.server_role == 'custom':
            role = {'label': 'Custom', 'expected_ports': state.custom_expected_ports,
                    'expected_services': state.custom_expected_services, 'desc': 'Custom profile'}
        else:
            role = SERVER_ROLES.get(state.server_role, SERVER_ROLES['general'])
        _parse_firewall(state, section(sudo_out, 'UFW'))
        _parse_ports(state, section(sudo_out, 'PORTS'), section(sudo_out, 'UDPPORTS'), section(sudo_out, 'LSOF'), role)
        _parse_ssh_config(state, section(sudo_out, 'SSHD'), has_keys, key_count, section(sudo_out, 'F2B'), section(sudo_out, 'F2BCONF'))
        _parse_logs(state, section(sudo_out, 'AUTHFAIL'), section(sudo_out, 'FAIL24'), section(sudo_out, 'ACCEPTED'))
        _parse_files(state, section(sudo_out, 'SUID'), section(sudo_out, 'ENVFILES'))
        _parse_app(state, section(sudo_out, 'SSL'), missing_headers, section(sudo_out, 'PGHBA'),
                   section(sudo_out, 'XRDP'), section(sudo_out, 'XRDPFW'), section(sudo_out, 'TOOLS'),
                   gw, xrdp_installed, section(sudo_out, 'PGLISTEN'), csp_needs_update=csp_needs_update)
        _parse_processes(state, section(sudo_out, 'PROCS'))
        _parse_services(state, section(sudo_out, 'SERVICES'), role)
        _parse_network(state, section(sudo_out, 'NETCONN'))
        _parse_kernel(state, section(sudo_out, 'SYSCTL'), section(sudo_out, 'KMODULES'),
                      section(sudo_out, 'COREDUMP'), section(sudo_out, 'SWAPENC'))
        _parse_filesystem(state, section(sudo_out, 'WORLDWRITE'), section(sudo_out, 'TMPSTICKY'))
        _parse_docker(state, section(sudo_out, 'DOCKER'))
        _parse_cron(state, section(sudo_out, 'CRONTABS'), user_cron)
        _parse_password_policy(state, section(sudo_out, 'PASSWD_POLICY'))
        _parse_dns(state, section(sudo_out, 'DNS'))
        _parse_audit(state, section(sudo_out, 'AUDITD'))
        _parse_apparmor(state, section(sudo_out, 'APPARMOR'))
        _parse_sudoers(state, section(sudo_out, 'SUDOERS'))

        state.progress = 95
        state.log(f"✓ Full scan complete")

    # Save scan history
    _save_scan_history(state)

    diff = state._compute_diff()
    if diff:
        nc, rc, sc = len(diff['new_findings']), len(diff['resolved_findings']), diff['score_change']
        state.log(f"═══ Score: {state.score}/100 | Δ {'+' if sc>=0 else ''}{sc} | +{nc} new, -{rc} resolved ═══")
    else:
        state.log(f"═══ Score: {state.score}/100 — {len(state.findings)} findings ═══")


def _set_empty_sudo_data(state, has_keys, key_count, missing_headers, gw, xrdp_installed):
    """Set placeholder data with not_scanned flags for all sudo-required modules."""
    ns = {"not_scanned": True, "reason": "Sudo access required — provide password and rescan"}
    state.data['firewall'] = {**ns, "active": None, "default_in": "unknown", "allowed_ports": [], "denied_ports": [], "blocked_ips": [], "rules": []}
    state.data['ports'] = []
    state.data['ports_meta'] = ns
    state.data['ssh'] = {**ns, "settings": [], "has_keys": has_keys, "key_count": key_count,
        "f2b_active": None, "f2b_banned_now": 0, "f2b_banned_total": 0, "f2b_banned_ips": []}
    state.data['logs'] = {**ns, "attackers": [], "failed_24h": 0, "accepted": []}
    state.data['files'] = {**ns, "suid_count": 0, "suid_dangerous": [], "env_files": []}
    state.data['app'] = {**ns, "ssl_certs": [], "nginx_missing_headers": missing_headers, "pg_issues": [],
        "gunicorn_workers": gw, "xrdp_installed": xrdp_installed, "security_tools": {}}
    state.data['processes'] = {**ns, "top": [], "suspicious": []}
    state.data['services'] = {**ns, "enabled": [], "risky": [], "risky_details": []}
    state.data['network'] = {**ns, "connections": [], "outbound": []}
    state.data['kernel'] = {**ns, "settings": [], "issues": []}
    state.data['filesystem'] = {**ns, "world_writable": [], "tmp_ok": True}
    state.data['docker'] = {**ns, "running": [], "issues": []}
    state.data['cron'] = {**ns, "jobs": []}
    state.data['password_policy'] = ns
    state.data['dns'] = {**ns, "resolvers": []}
    state.data['audit'] = {**ns, "active": None, "rules": 0}


# ─── Parse functions ───

def _parse_firewall(state, ufw_out):
    fw = {"active": False, "default_in": "unknown", "allowed_ports": [], "denied_ports": [], "blocked_ips": [], "rules": []}
    for line in ufw_out.split('\n'):
        if re.match(r'^Status:\s*active', line, re.IGNORECASE):
            fw['active'] = True; break
    dm = re.search(r'Default:\s*(\w+)\s*\(incoming\)', ufw_out)
    if dm: fw['default_in'] = dm.group(1).lower()
    allowed, denied, blocked_ips = set(), set(), set()
    for line in ufw_out.split('\n'):
        line = line.strip()
        if not line: continue
        pm = re.match(r'^(\d+)(?:/(\w+))?\s+ALLOW\s+IN\s+Anywhere', line)
        if pm: allowed.add(pm.group(1))
        nm = re.match(r'^(Nginx Full|Nginx HTTP|Nginx HTTPS|Apache Full|OpenSSH)\s+ALLOW', line)
        if nm:
            n = nm.group(1)
            if 'Full' in n or 'HTTP' in n: allowed.add('80')
            if 'Full' in n or 'HTTPS' in n: allowed.add('443')
            if 'SSH' in n or 'OpenSSH' in n: allowed.add('22')
        dp = re.match(r'^(\d+)(?:/\w+)?\s+DENY', line)
        if dp: denied.add(dp.group(1))
        di = re.search(r'DENY\s+IN\s+(\d+\.\d+\.\d+\.\d+)', line)
        if di: blocked_ips.add(di.group(1))
        if any(a in line for a in ['ALLOW', 'DENY', 'REJECT', 'LIMIT']):
            fw['rules'].append(line)
    fw['allowed_ports'] = sorted(allowed, key=lambda x: int(x))
    fw['denied_ports'] = sorted(denied, key=lambda x: int(x))
    fw['blocked_ips'] = sorted(blocked_ips)
    state.data['firewall'] = fw
    if not fw['active']:
        state.add_finding("CRITICAL", "Firewall inactive",
            "UFW (Uncomplicated Firewall) is not enabled. Without a firewall, every listening service on this server "
            "is directly accessible from the internet. Attackers can reach databases, admin panels, debug ports, and "
            "internal services that should never be exposed. A firewall is the most fundamental layer of defense — "
            "enable it with a default-deny incoming policy and explicitly allow only required ports (e.g., 22, 80, 443).",
            "sudo ufw allow 22/tcp && sudo ufw default deny incoming && sudo ufw --force enable",
            "sudo ufw disable", cis_ref="CIS 3.5.1.1")
    elif fw['default_in'] != 'deny':
        state.add_finding("HIGH", "Default incoming not deny",
            f"Firewall default incoming policy is '{fw['default_in']}' instead of 'deny'. This means any new service "
            "that starts listening on a port is automatically accessible from the internet. A default-deny policy ensures "
            "only explicitly allowed ports are reachable, so accidental exposure of new services cannot happen.",
            "sudo ufw allow 22/tcp && sudo ufw default deny incoming", cis_ref="CIS 3.5.1.1")
    state.log(f"✓ Firewall: {'active' if fw['active'] else 'INACTIVE'}")


def _parse_ports(state, tcp_out, udp_out, lsof_out, role=None):
    lsof_map = {}
    for line in lsof_out.split('\n'):
        parts = line.strip().split()
        if len(parts) >= 2:
            pm = re.search(r':(\d+)$', parts[1])
            if pm: lsof_map[pm.group(1)] = parts[0]

    fw = state.data.get('firewall', {})
    fw_allowed = set(fw.get('allowed_ports', []))
    fw_active = fw.get('active', False)
    fw_default = fw.get('default_in', 'unknown')

    expected_ports = (role or {}).get('expected_ports', {'22'})

    def is_allowed(port):
        if not fw_active: return True
        if port in fw_allowed: return True
        return fw_default != 'deny'

    ports = []
    for proto, out in [('tcp', tcp_out), ('udp', udp_out)]:
        for line in out.split('\n'):
            if 'LISTEN' not in line and 'UNCONN' not in line: continue
            parts = line.split()
            if len(parts) < 5: continue
            local = parts[3]
            port_m = re.search(r':(\d+)$', local)
            proc_m = re.search(r'users:\(\("([^"]+)"', line)
            addr = re.sub(r':\d+$', '', local)
            if port_m:
                pnum = port_m.group(1)
                pname = proc_m.group(1) if proc_m else lsof_map.get(pnum, "unknown")
                is_local = addr in ("127.0.0.1", "[::1]", "127.0.0.53", "127.0.0.54", "::1")
                expected = pnum in expected_ports
                fw_ok = is_allowed(pnum)
                if is_local: exposure = "localhost"
                elif fw_ok and expected: exposure = "expected"
                elif fw_ok:
                    exposure = "exposed"
                    role_label = (role or {}).get('label', 'this server role')
                    state.add_finding("HIGH", f"Port {pnum}/{proto} ({pname}) exposed",
                        f"Port {pnum} ({pname}) is bound to {addr} and reachable from the network, but is NOT in the "
                        f"expected ports for '{role_label}'. Unexpected open ports are a common attack vector — each "
                        "exposed service can be probed for vulnerabilities, brute-forced, or exploited. If this service "
                        "is not intentionally public-facing, block it with a firewall rule.",
                        f"sudo ufw deny {pnum}/{proto}")
                else: exposure = "filtered"
                ports.append({"port": pnum, "proto": proto, "addr": addr, "process": pname, "exposure": exposure})

    seen = {}
    for p in ports:
        k = f"{p['port']}-{p['proto']}"
        if k not in seen or (p['process'] != 'unknown'): seen[k] = p
    state.data['ports'] = sorted(seen.values(), key=lambda x: int(x['port']))
    exposed = len([p for p in state.data['ports'] if p['exposure'] == 'exposed'])
    state.log(f"✓ Ports: {len(state.data['ports'])} total, {exposed} exposed")


def _parse_ssh_config(state, sshd_out, has_keys, key_count, f2b_out, f2b_conf_out=''):
    # (key, safe_vals, severity, fix_val, why_it_matters)
    checks = [
        ("PermitRootLogin", ["no", "prohibit-password"], "HIGH", "no",
         "Allows direct root login over SSH. If an attacker guesses or brute-forces the root password, they immediately "
         "have full system control. Disabling forces attackers to compromise a regular user first, then escalate — "
         "giving you two layers of defense and an audit trail of which user account was used."),
        ("PasswordAuthentication", ["no"], "MEDIUM", "no",
         "Allows password-based SSH login. Passwords can be brute-forced — even strong passwords are vulnerable to "
         "credential stuffing attacks using leaked databases. SSH key authentication is immune to brute force "
         "since keys are 2048+ bit cryptographic secrets. Disable after confirming SSH keys work."),
        ("PermitEmptyPasswords", ["no"], "CRITICAL", "no",
         "Allows accounts with blank passwords to log in via SSH. An attacker only needs to guess a valid username "
         "to gain shell access. This is one of the most dangerous SSH misconfigurations possible."),
        ("PubkeyAuthentication", ["yes"], "MEDIUM", "yes",
         "Public key authentication is disabled. This is the most secure SSH authentication method — it uses "
         "cryptographic key pairs instead of passwords. Without it, the server is limited to weaker auth methods."),
        ("X11Forwarding", ["no"], "LOW", "no",
         "X11 forwarding allows GUI applications to be displayed over SSH. If enabled, a compromised SSH session "
         "could exploit X11 protocol vulnerabilities to capture keystrokes or screenshots on the admin's machine."),
        ("MaxAuthTries", None, "INFO", None,
         "Controls how many authentication attempts are allowed per SSH connection before disconnecting."),
    ]
    # SSH default values when not explicitly configured
    SSH_DEFAULTS = {
        'PermitRootLogin': 'prohibit-password',
        'PasswordAuthentication': 'yes',
        'PermitEmptyPasswords': 'no',
        'PubkeyAuthentication': 'yes',
        'X11Forwarding': 'no',
        'MaxAuthTries': '6',
    }
    settings = []
    for key, safe_vals, sev, fix_val, why in checks:
        m = re.search(rf'^{key}\s+(.+)', sshd_out, re.MULTILINE | re.IGNORECASE)
        if m:
            val = m.group(1).strip()
        else:
            val = SSH_DEFAULTS.get(key, '(unknown)')
        is_safe = safe_vals is None or val.lower() in [s.lower() for s in safe_vals]
        explicit = bool(m)
        settings.append({"key": key, "value": val, "safe": is_safe, "sev": sev,
                         "explicit": explicit})
        if not is_safe and fix_val:
            default_note = " (not explicitly set — using SSH default)" if not explicit else ""
            state.add_finding(sev, f"SSH {key} = {val}",
                f"Current value: {val}{default_note} (should be: {fix_val}). {why}",
                f"sudo sed -i '/^#*\\s*{key}/c\\{key} {fix_val}' /etc/ssh/sshd_config && sudo systemctl restart ssh",
                f"sudo sed -i '/^{key} {fix_val}/c\\#{key} {fix_val}' /etc/ssh/sshd_config && sudo systemctl restart ssh",
                cis_ref="CIS 5.3")

    f2b_active = "sshd" in f2b_out.lower() and "F2B_INACTIVE" not in f2b_out
    banned_now = banned_total = 0; banned_ips = []
    if f2b_active:
        bm = re.search(r'Currently banned:\s*(\d+)', f2b_out); banned_now = int(bm.group(1)) if bm else 0
        tm = re.search(r'Total banned:\s*(\d+)', f2b_out); banned_total = int(tm.group(1)) if tm else 0
        bl = re.search(r'Banned IP list:\s*(.+)', f2b_out); banned_ips = bl.group(1).strip().split() if bl else []
    else:
        state.add_finding("MEDIUM", "fail2ban not active",
            "fail2ban is not running. Without it, attackers can make unlimited SSH login attempts with no consequences. "
            "Automated bots continuously scan the internet for SSH servers and attempt thousands of password combinations. "
            "fail2ban monitors auth logs and automatically blocks IPs after repeated failures, dramatically reducing "
            "brute force exposure.",
            "sudo apt-get update; sudo apt-get install fail2ban -y && sudo systemctl enable --now fail2ban")

    # Parse f2b config — check bantime, maxretry, findtime
    f2b_config = {"bantime": None, "maxretry": None, "findtime": None, "strict": False}
    if f2b_active and f2b_conf_out:
        parts = f2b_conf_out.split('---')
        # fail2ban-client get outputs are in order: bantime, maxretry, findtime
        for i, key in enumerate(['bantime', 'maxretry', 'findtime']):
            if i < len(parts):
                val_str = parts[i].strip()
                m = re.search(r'(\d+)', val_str)
                if m:
                    f2b_config[key] = int(m.group(1))

        bt = f2b_config['bantime'] or 600
        mr = f2b_config['maxretry'] or 5
        ft = f2b_config['findtime'] or 600

        # Check if config is weak
        is_weak = bt < 3600 or mr > 3 or ft < 600
        f2b_config['strict'] = not is_weak

        if is_weak:
            detail_parts = []
            if bt < 3600: detail_parts.append(f"bantime={bt}s ({bt//60}min)")
            if mr > 3: detail_parts.append(f"maxretry={mr}")
            if ft < 600: detail_parts.append(f"findtime={ft}s")
            state.add_finding("MEDIUM", "fail2ban config is too lenient",
                f"Current settings: {', '.join(detail_parts)}. With these settings, attackers are unbanned quickly "
                "and can resume brute-forcing after a short wait. A 10-minute ban barely slows down automated tools "
                "that cycle through thousands of IPs. Recommended: 24h ban (86400s), max 3 retries, 1h findtime, "
                "with escalating bans (2x multiplier) so repeat offenders are blocked for days then weeks.",
                "sudo bash -c 'mkdir -p /etc/fail2ban && cat > /etc/fail2ban/jail.local << EOF\n[DEFAULT]\nbantime = 86400\nfindtime = 3600\nmaxretry = 3\nbantime.increment = true\nbantime.factor = 2\nbantime.maxtime = 604800\n\n[sshd]\nenabled = true\nEOF' && sudo systemctl restart fail2ban",
                "sudo rm -f /etc/fail2ban/jail.local && sudo systemctl restart fail2ban")

    state.data['ssh'] = {"settings": settings, "has_keys": has_keys, "key_count": key_count,
        "f2b_active": f2b_active, "f2b_banned_now": banned_now, "f2b_banned_total": banned_total,
        "f2b_banned_ips": banned_ips, "f2b_config": f2b_config}
    state.log(f"✓ SSH: f2b={'on' if f2b_active else 'off'}, keys={key_count}" +
        (f", bantime={f2b_config['bantime']}s" if f2b_config['bantime'] else ""))


def _parse_logs(state, atk_out, cnt_out, acc_out):
    fw = state.data.get('firewall', {})
    blocked_ips = set(fw.get('blocked_ips', []))
    banned_ips = set(state.data.get('ssh', {}).get('f2b_banned_ips', []))
    attackers = []
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    for line in atk_out.split('\n'):
        m = re.match(r'\s*(\d+)\s+(\S+)', line)
        if m:
            ip = m.group(2)
            # Only include valid IP addresses — skip paths, usernames, etc.
            if not ip_pattern.match(ip):
                continue
            attackers.append({"count": int(m.group(1)), "ip": ip, "blocked": ip in blocked_ips, "banned": ip in banned_ips})
    try: failed_24h = int(cnt_out.strip())
    except: failed_24h = 0
    if failed_24h > 100:
        state.add_finding("HIGH", f"{failed_24h} failed SSH in 24h",
            f"Your server received {failed_24h} failed SSH login attempts in the last 24 hours, indicating an active "
            "brute force attack. Attackers are systematically guessing username/password combinations. If any account "
            "has a weak password, they may gain access. Ensure fail2ban is active, SSH keys are required (disable "
            "PasswordAuthentication), and consider changing the SSH port or restricting source IPs via firewall.")
    accepted = []
    for line in acc_out.split('\n'):
        m = re.search(r'Accepted\s+(\w+)\s+for\s+(\w+)\s+from\s+(\S+)', line)
        if m: accepted.append({"method": m.group(1), "user": m.group(2), "ip": m.group(3)})
    state.data['logs'] = {"attackers": attackers, "failed_24h": failed_24h, "accepted": accepted}
    state.log(f"✓ Logs: {failed_24h} failed/24h, {len(attackers)} attacker IPs")


def _parse_files(state, suid_out, env_out):
    suid = [l.strip() for l in suid_out.split('\n') if l.strip()]
    dangerous_bins = ['/usr/bin/nmap', '/usr/bin/python', '/usr/bin/perl', '/usr/bin/vim',
                      '/usr/bin/find', '/usr/bin/bash', '/usr/bin/env', '/usr/bin/docker']
    dangerous = [s for s in suid if any(d in s for d in dangerous_bins)]
    if dangerous:
        for d in dangerous:
            bin_name = os.path.basename(d)
            state.add_finding("HIGH", f"Dangerous SUID: {d}",
                f"The SUID bit is set on {d}. When a binary has SUID set, it runs with the file owner's privileges "
                f"(usually root) regardless of who executes it. Tools like {bin_name} can be abused to spawn root "
                "shells, read/write arbitrary files, or execute commands as root. See GTFOBins for known escalation "
                "techniques. Remove the SUID bit unless there is a specific operational need.",
                f"sudo chmod u-s {d}", f"sudo chmod u+s {d}", cis_ref="CIS 6.1.13")
    envs = []
    for line in env_out.split('\n'):
        if not line.strip(): continue
        parts = line.rsplit(' ', 1)
        path = parts[0]; perms = parts[1] if len(parts) > 1 else "?"
        ok = perms in ('600', '400')
        envs.append({"path": path, "perms": perms, "ok": ok})
        if not ok and perms != '?':
            state.add_finding("HIGH", f".env weak permissions: {path}",
                f"Permissions {perms} on {path}. .env files typically contain API keys, database passwords, "
                "and other secrets. Current permissions allow other users on this system to read the file. "
                "Any compromised service or user account could extract these credentials. "
                "Set to 600 (owner read/write only) to prevent unauthorized access.",
                f"sudo chmod 600 {path}")
    state.data['files'] = {"suid_count": len(suid), "suid_dangerous": dangerous, "env_files": envs}


def _parse_app(state, ssl_out, missing_headers, pg_out, rdp_st, rdp_fw, tools_out, gw, xrdp_installed, pg_listen='', csp_needs_update=False):
    certs = []
    for m in re.finditer(r'=CERT= (.+?)\n(.*?)(?==CERT=|\Z)', ssl_out, re.DOTALL):
        path, info = m.group(1), m.group(2)
        exp_m = re.search(r'notAfter=(.+)', info)
        if exp_m:
            try:
                exp = datetime.strptime(exp_m.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
                days = (exp - datetime.now()).days
                certs.append({"path": path, "days_left": days})
                if days < 30:
                    state.add_finding("CRITICAL" if days < 7 else "HIGH", f"SSL cert expires in {days} days",
                        f"Certificate at {path} expires in {days} days. When SSL certificates expire, browsers show "
                        "security warnings that drive users away and break API integrations. Expired certs also disable "
                        "HTTPS encryption, exposing all traffic (including login credentials and session tokens) to "
                        "interception. Renew immediately with certbot or your certificate provider.",
                        "sudo certbot renew")
            except: pass
    if missing_headers:
        # Build nginx snippet with only missing headers
        header_lines = []
        header_map = {
            'X-Frame-Options': 'add_header X-Frame-Options "SAMEORIGIN" always;',
            'X-Content-Type-Options': 'add_header X-Content-Type-Options "nosniff" always;',
            'Content-Security-Policy': "add_header Content-Security-Policy \"default-src 'self' https:; style-src 'self' 'unsafe-inline' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; img-src 'self' data: https: blob:; font-src 'self' data: https:; connect-src 'self' https: wss: ws:; media-src 'self' https: blob:; frame-ancestors 'self'; object-src 'none'; base-uri 'self'\" always;",
            'Strict-Transport-Security': 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
        }
        for h in missing_headers:
            if h in header_map:
                header_lines.append(header_map[h])
        if header_lines:
            import base64 as _b64
            header_content = '\n'.join(header_lines)
            encoded_headers = _b64.b64encode(header_content.encode()).decode()
            # Write snippet via base64 decode (avoids all quoting issues),
            # then inject include into each site config after server_name line
            fix_cmd = (f"sudo mkdir -p /etc/nginx/snippets && "
                       f"echo '{encoded_headers}' | base64 -d | sudo tee /etc/nginx/snippets/security-headers.conf > /dev/null && "
                       f"for f in /etc/nginx/sites-enabled/*; do "
                       f"sudo grep -q 'security-headers' \"$f\" 2>/dev/null || "
                       f"sudo sed -i '/server_name/a \\    include /etc/nginx/snippets/security-headers.conf;' \"$f\" 2>/dev/null; "
                       f"done && "
                       f"sudo nginx -t && sudo systemctl reload nginx")
            undo_cmd = ("sudo rm -f /etc/nginx/snippets/security-headers.conf && "
                        "sudo sed -i '/security-headers/d' /etc/nginx/sites-enabled/* 2>/dev/null; "
                        "sudo nginx -t && sudo systemctl reload nginx")
            state.add_finding("MEDIUM", "Missing nginx security headers",
                f"Missing: {', '.join(missing_headers)}. Security headers instruct browsers to enable built-in "
                "protections: X-Frame-Options prevents clickjacking (embedding your site in a malicious iframe), "
                "X-Content-Type-Options stops MIME-sniffing attacks, Content-Security-Policy blocks XSS and data "
                "injection, and Strict-Transport-Security forces HTTPS and prevents SSL-stripping MITM attacks. "
                "Without these, users visiting your site are exposed to common web attack vectors.",
                fix_cmd, undo_cmd)
        else:
            state.add_finding("MEDIUM", "Missing nginx security headers",
                f"Missing: {', '.join(missing_headers)}. These headers protect users from clickjacking, XSS, "
                "MIME-sniffing, and SSL-stripping attacks. See OWASP Secure Headers Project for configuration guidance.")

    # Check for overly-restrictive CSP that breaks CDN resources
    if csp_needs_update:
        import base64 as _b64
        updated_csp = "add_header Content-Security-Policy \"default-src 'self' https:; style-src 'self' 'unsafe-inline' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; img-src 'self' data: https: blob:; font-src 'self' data: https:; connect-src 'self' https: wss: ws:; media-src 'self' https: blob:; frame-ancestors 'self'; object-src 'none'; base-uri 'self'\" always;"
        # Build complete updated snippet with all headers
        all_headers = [
            'add_header X-Frame-Options "SAMEORIGIN" always;',
            'add_header X-Content-Type-Options "nosniff" always;',
            updated_csp,
            'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
        ]
        encoded = _b64.b64encode('\n'.join(all_headers).encode()).decode()
        fix_cmd = (f"echo '{encoded}' | base64 -d | sudo tee /etc/nginx/snippets/security-headers.conf > /dev/null && "
                   f"sudo nginx -t && sudo systemctl reload nginx")
        undo_cmd = None  # No undo — this is strictly an improvement
        state.add_finding("LOW", "Overly restrictive Content-Security-Policy",
            "The current CSP only allows resources from 'self', which blocks CSS, JavaScript, and fonts loaded from "
            "CDNs (e.g. cdnjs.cloudflare.com, Google Fonts, Bootstrap CDN). This causes blank pages or broken styling "
            "on applications that use external resources. The fix updates the CSP to allow any HTTPS source while still "
            "blocking unsafe protocols, inline objects, and cross-origin framing.",
            fix_cmd, undo_cmd)

    # ── PostgreSQL analysis ──
    pg_issues = []
    pg_localhost_only = 'localhost' in pg_listen.lower() or ('*' not in pg_listen and '0.0.0.0' not in pg_listen)

    # Parse each pg_hba line for context
    has_wide_open = False
    has_trust = False
    wide_lines = []
    for line in pg_out.split('\n'):
        line = line.strip()
        if not line: continue
        parts = line.split()
        if len(parts) < 4: continue
        # Format: TYPE DATABASE USER ADDRESS METHOD
        conn_type = parts[0]    # local, host, hostssl, hostnossl
        auth_method = parts[-1]  # trust, md5, scram-sha-256, peer, etc.

        # Check for trust auth on non-local connections
        if auth_method.lower() == 'trust' and conn_type != 'local':
            has_trust = True
            pg_issues.append(f"Trust auth on {conn_type}: {line}")

        # Check for wide-open network access
        if conn_type in ('host', 'hostssl', 'hostnossl'):
            addr = parts[3] if len(parts) > 3 else ''
            if addr in ('0.0.0.0/0', '::/0', 'all'):
                has_wide_open = True
                wide_lines.append(line)

    # Determine PG config file path dynamically
    pg_hba_path = "/etc/postgresql/*/main/pg_hba.conf"

    if has_trust and has_wide_open:
        pg_issues.insert(0, "Trust auth + open to all IPs")
        state.add_finding("CRITICAL", "PostgreSQL: trust auth open to all IPs",
            "pg_hba.conf uses 'trust' authentication AND allows connections from 0.0.0.0/0. This means ANYONE "
            "from ANY IP address can connect to PostgreSQL as ANY database user without a password. This is the "
            "most dangerous PostgreSQL misconfiguration — an attacker can read, modify, or delete all data, "
            "create superuser accounts, and potentially execute operating system commands via COPY or extensions.",
            f"sudo sed -i 's/\\bhost\\b\\(.*\\)0\\.0\\.0\\.0\\/0\\(.*\\)trust/host\\1127.0.0.1\\/32\\2scram-sha-256/' {pg_hba_path} && sudo systemctl reload postgresql",
            f"sudo systemctl reload postgresql")
    elif has_trust:
        pg_issues.insert(0, "Trust auth (no password)")
        state.add_finding("HIGH", "PostgreSQL: trust authentication on network connections",
            "pg_hba.conf uses 'trust' authentication for network connections, meaning no password is required to "
            "connect. Any user or process that can reach the PostgreSQL port can log in as any database user, "
            "including the superuser. Switch to scram-sha-256 to require password authentication.",
            f"sudo sed -i 's/\\btrust\\b/scram-sha-256/g' {pg_hba_path} && sudo systemctl reload postgresql",
            f"sudo systemctl reload postgresql")
    elif has_wide_open:
        if pg_localhost_only:
            pg_issues.append("pg_hba.conf allows 0.0.0.0/0 (but PG listens on localhost only)")
            state.add_finding("LOW", "PostgreSQL pg_hba.conf has 0.0.0.0/0 (localhost-only)",
                "pg_hba.conf allows connections from all IPs (0.0.0.0/0), but PostgreSQL currently only listens "
                "on localhost so it is not externally reachable. However, if listen_addresses is ever changed, this "
                "would immediately expose the database to the internet. Tighten pg_hba.conf to 127.0.0.1/32 now.",
                f"sudo sed -i 's|0\\.0\\.0\\.0/0|127.0.0.1/32|g' {pg_hba_path} && sudo sed -i 's|::/0|::1/128|g' {pg_hba_path} && sudo systemctl reload postgresql",
                f"sudo systemctl reload postgresql")
        else:
            pg_issues.append("Open to all IPs AND listening on all interfaces")
            state.add_finding("CRITICAL", "PostgreSQL exposed to all IPs",
                f"PostgreSQL listen_addresses is NOT restricted to localhost AND pg_hba.conf allows 0.0.0.0/0. "
                "This means the database port is accessible from the entire internet. Attackers can brute-force "
                "credentials, exploit known PostgreSQL vulnerabilities, or use default/weak passwords to access "
                "all stored data. Restrict listen_addresses to 'localhost' and tighten pg_hba.conf immediately.",
                f"sudo sed -i \"s/^#*listen_addresses.*/listen_addresses = 'localhost'/\" /etc/postgresql/*/main/postgresql.conf && "
                f"sudo sed -i 's|0\\.0\\.0\\.0/0|127.0.0.1/32|g' {pg_hba_path} && "
                f"sudo sed -i 's|::/0|::1/128|g' {pg_hba_path} && "
                f"sudo systemctl restart postgresql",
                f"sudo systemctl reload postgresql")

    rdp_exposed = 'ALLOW' in rdp_fw and 'Anywhere' in rdp_fw
    if rdp_exposed:
        state.add_finding("HIGH", "RDP (3389) exposed to internet",
            "xRDP is running and port 3389 is allowed through the firewall from any source. RDP is one of the most "
            "targeted protocols — ransomware operators routinely brute-force RDP credentials or exploit RDP vulnerabilities "
            "(like BlueKeep/CVE-2019-0708) to gain initial access. If remote desktop is needed, restrict access to a VPN "
            "or specific trusted IP addresses only.",
            "sudo ufw deny 3389")
    tools = {}
    for line in tools_out.split('\n'):
        if ':' in line:
            n, v = line.split(':', 1)
            tools[n.strip()] = v.strip() == 'YES'
    state.data['app'] = {"ssl_certs": certs, "nginx_missing_headers": missing_headers, "pg_issues": pg_issues,
        "pg_localhost_only": pg_localhost_only, "pg_listen": pg_listen.strip(),
        "gunicorn_workers": gw, "xrdp_installed": xrdp_installed, "xrdp_running": 'active' in rdp_st.strip(),
        "xrdp_exposed": rdp_exposed, "security_tools": tools}
    state.log(f"✓ PostgreSQL: {'localhost-only' if pg_localhost_only else 'EXPOSED'}, {len(pg_issues)} issues")


def _parse_processes(state, procs_out):
    """Parse running processes, flag suspicious ones."""
    top = []
    suspicious = []
    suspicious_names = ['nc ', 'ncat', 'netcat', 'socat', 'tcpdump', 'nmap', 'masscan',
                        'hydra', 'john', 'hashcat', 'msfconsole', 'reverse', 'bind.*shell',
                        'cryptominer', 'xmrig', 'minerd', 'kworker.*mine']
    for line in procs_out.split('\n'):
        if not line.strip() or line.startswith('USER'): continue
        parts = line.split(None, 10)
        if len(parts) >= 11:
            proc = {"user": parts[0], "pid": parts[1], "cpu": parts[2], "mem": parts[3], "cmd": parts[10]}
            top.append(proc)
            cmd_lower = proc['cmd'].lower()
            for s in suspicious_names:
                if re.search(s, cmd_lower):
                    suspicious.append(proc)
                    state.add_finding("CRITICAL", f"Suspicious process: {proc['cmd'][:60]}",
                        f"PID {proc['pid']} running as '{proc['user']}': {proc['cmd'][:100]}. "
                        f"This process matches known attack tool signatures ({s}). Legitimate servers rarely run "
                        "network sniffers, port scanners, password crackers, or reverse shells. This may indicate an "
                        "active compromise — an attacker may have gained access and is using this tool to pivot, "
                        "exfiltrate data, or mine cryptocurrency. Investigate immediately and check auth logs for "
                        "how the attacker gained access.",
                        f"sudo kill -9 {proc['pid']}",
                        None)
                    break
            try:
                if float(proc['cpu']) > 90:
                    state.add_finding("MEDIUM", f"High CPU: {proc['cmd'][:40]}",
                        f"PID {proc['pid']} is consuming {proc['cpu']}% CPU. Sustained high CPU usage can indicate "
                        "cryptocurrency mining malware, a stuck/runaway process, or a denial-of-service condition. "
                        "Cryptominers are the most common payload deployed after a server compromise — they consume "
                        "resources silently while generating revenue for the attacker.",
                        f"sudo kill -15 {proc['pid']}",
                        None)
            except: pass
    state.data['processes'] = {"top": top[:25], "suspicious": suspicious}
    state.log(f"✓ Processes: {len(top)} running, {len(suspicious)} suspicious")


def _parse_services(state, svc_out, role=None):
    """Parse enabled services using CIS Benchmark taxonomy with role + firewall awareness.
    
    If a risky service is running but its port is blocked by the firewall (not externally 
    reachable), the severity is downgraded and the finding detail reflects reduced risk.
    """
    # Service → typical listening ports (for firewall cross-reference)
    SERVICE_PORTS = {
        'telnet': ['23'], 'rsh': ['514'], 'rlogin': ['513'], 'rexec': ['512'],
        'tftp': ['69'], 'vsftpd': ['21'], 'proftpd': ['21'], 'pure-ftpd': ['21'],
        'snmpd': ['161'], 'rpcbind': ['111'], 'nfs-server': ['2049'], 'nfs-kernel-server': ['2049'],
        'avahi-daemon': ['5353'], 'cups': ['631'], 'cups-browsed': ['631'],
        'xrdp': ['3389'], 'bind9': ['53'], 'named': ['53'], 'squid': ['3128'],
        'postfix': ['25', '587'], 'sendmail': ['25'], 'exim4': ['25'],
        'dovecot': ['143', '993', '110', '995'], 'courier-imap': ['143', '993'],
        'mysql': ['3306'], 'mariadb': ['3306'], 'mongod': ['27017'],
        'redis-server': ['6379'], 'memcached': ['11211'], 'elasticsearch': ['9200'],
    }

    # Severity downgrade map: if firewalled, what does the severity become?
    SEV_DOWNGRADE = {'CRITICAL': 'MEDIUM', 'HIGH': 'LOW', 'MEDIUM': 'LOW', 'LOW': 'LOW'}

    # Build firewall awareness from already-parsed data
    fw = state.data.get('firewall', {})
    fw_active = fw.get('active', False)
    fw_default_deny = fw.get('default_in', 'unknown') == 'deny'
    fw_allowed = set(fw.get('allowed_ports', []))

    # Also check parsed port data for actual exposure
    port_exposure = {}
    for p in state.data.get('ports', []):
        port_exposure[p['port']] = p.get('exposure', 'unknown')

    def is_port_externally_reachable(service_name):
        """Check if any of a service's typical ports are reachable from outside."""
        ports = SERVICE_PORTS.get(service_name, [])
        if not ports:
            return True  # Unknown ports — assume reachable (conservative)
        if not fw_active:
            return True  # No firewall — everything reachable
        for port in ports:
            # Check actual port scan data first (most reliable)
            exp = port_exposure.get(port)
            if exp in ('exposed', 'expected'):
                return True
            # Fall back to firewall rules
            if port in fw_allowed:
                return True
        # Firewall active + default deny + port not in allowed list = blocked
        return not fw_default_deny

    enabled = []
    risky_found = []
    risky_details = []
    role_expected = (role or {}).get('expected_services', set())

    cat_labels = {'legacy': 'Legacy/insecure protocol', 'file_transfer': 'Insecure file transfer',
        'network': 'Network service', 'desktop': 'Desktop/GUI service', 'remote_access': 'Remote access',
        'dns': 'DNS server', 'proxy': 'Proxy service', 'mail': 'Mail service', 'database': 'Database'}

    for line in svc_out.split('\n'):
        line = line.strip()
        if not line: continue
        parts = line.split()
        if len(parts) >= 2:
            name = parts[0].replace('.service', '')
            enabled.append(name)
            if name in CIS_RISKY_SERVICES:
                info = CIS_RISKY_SERVICES[name]
                externally_reachable = is_port_externally_reachable(name)
                detail = {**info, 'name': name, 'role_expected': name in role_expected,
                          'firewalled': not externally_reachable}
                risky_details.append(detail)
                if name in role_expected:
                    continue  # Expected for this role — don't flag

                risky_found.append(name)
                base_sev = info['sev']
                cat_label = cat_labels.get(info['cat'], info['cat'])
                role_label = (role or {}).get('label', 'this server')
                svc_ports = SERVICE_PORTS.get(name, [])
                port_str = '/'.join(svc_ports) if svc_ports else '?'

                if externally_reachable:
                    # Full severity — port is reachable from the internet
                    state.add_finding(base_sev,
                        f"Service: {name} — {info['reason'][:60]}",
                        f"[{info['cis']}] Category: {cat_label}. {info['reason']}. "
                        f"Port {port_str} is REACHABLE from the internet (firewall allows it). "
                        f"This service is not expected for the '{role_label}' server role. "
                        "An attacker can directly probe and exploit this service from anywhere.",
                        f"sudo systemctl disable {name} && sudo systemctl stop {name}",
                        f"sudo systemctl enable {name} && sudo systemctl start {name}",
                        cis_ref=info['cis'])
                else:
                    # Downgraded severity — port is blocked by firewall
                    downgraded_sev = SEV_DOWNGRADE.get(base_sev, 'LOW')
                    state.add_finding(downgraded_sev,
                        f"Service: {name} (firewalled) — {info['reason'][:50]}",
                        f"[{info['cis']}] Category: {cat_label}. {info['reason']}. "
                        f"Port {port_str} is BLOCKED by the firewall, so this service is not directly "
                        "reachable from the internet. Risk is reduced but not eliminated — if an attacker "
                        "gains initial access via another vector (e.g., a web vulnerability), this service "
                        "becomes available for lateral movement or privilege escalation. "
                        f"Consider disabling if not needed for the '{role_label}' role.",
                        f"sudo systemctl disable {name} && sudo systemctl stop {name}",
                        f"sudo systemctl enable {name} && sudo systemctl start {name}",
                        cis_ref=info['cis'])

    state.data['services'] = {"enabled": enabled, "risky": risky_found, "risky_details": risky_details}
    state.log(f"✓ Services: {len(enabled)} enabled, {len(risky_found)} risky")


def _parse_network(state, conn_out):
    """Parse active network connections — especially outbound."""
    connections = []
    outbound = []
    for line in conn_out.split('\n'):
        if not line.strip() or 'ESTAB' not in line: continue
        parts = line.split()
        if len(parts) >= 6:
            proto = parts[0]
            local = parts[3]
            remote = parts[4]
            proc_m = re.search(r'users:\(\("([^"]+)"', line)
            pname = proc_m.group(1) if proc_m else "?"
            conn = {"proto": proto, "local": local, "remote": remote, "process": pname}
            connections.append(conn)
            # Outbound = local port is ephemeral (>1024), remote is well-known
            remote_port = remote.rsplit(':', 1)[-1] if ':' in remote else '?'
            local_port = local.rsplit(':', 1)[-1] if ':' in local else '?'
            try:
                if int(local_port) > 1024:
                    outbound.append(conn)
            except: pass

    state.data['network'] = {"connections": connections[:50], "outbound": outbound[:30]}
    state.log(f"✓ Network: {len(connections)} active, {len(outbound)} outbound")


def _parse_kernel(state, sysctl_out, kmod_out, coredump_out, swap_out):
    """Parse kernel security settings using CIS Benchmark checks."""
    settings = []
    issues = []

    for line in sysctl_out.split('\n'):
        m = re.match(r'(\S+)\s*=\s*(\S+)', line)
        if m:
            key, val = m.group(1), m.group(2)
            if key in CIS_SYSCTL_CHECKS:
                exp_val, issue_desc, cis_ref, sev = CIS_SYSCTL_CHECKS[key]
                ok = val == exp_val
                settings.append({"key": key, "value": val, "expected": exp_val, "ok": ok,
                                 "cis_ref": cis_ref, "description": issue_desc})
                if not ok:
                    issues.append({"key": key, "desc": issue_desc, "cis_ref": cis_ref})
                    state.add_finding(sev, f"Kernel: {key}",
                        f"{key} = {val} (expected {exp_val}). {issue_desc}",
                        f"sudo sysctl -w {key}={exp_val} && echo '{key}={exp_val}' | sudo tee -a /etc/sysctl.d/99-aegis-hardening.conf",
                        f"sudo sysctl -w {key}={val} && sudo sed -i '/{key}/d' /etc/sysctl.d/99-aegis-hardening.conf",
                        cis_ref=cis_ref)

    # Core dumps
    if coredump_out.strip() and 'core' in coredump_out.lower() and '|' not in coredump_out:
        state.add_finding("LOW", "Core dumps to file",
            "When SUID programs crash, their memory is dumped to disk. This memory may contain passwords, encryption keys, "
            "database credentials, or other sensitive data from privileged processes. An attacker who can trigger a crash and "
            "read the dump file can extract these secrets. Piping to /bin/false prevents dump files from being written.",
            "echo '|/bin/false' | sudo tee /proc/sys/kernel/core_pattern")

    # Kernel modules
    modules = [l.split()[0] for l in kmod_out.split('\n') if l.strip() and not l.startswith('Module')]

    state.data['kernel'] = {"settings": settings, "issues": issues, "modules": modules[:30],
        "core_pattern": coredump_out.strip(), "swap": swap_out.strip()}


def _parse_filesystem(state, worldwrite_out, tmp_out):
    """Parse world-writable dirs and /tmp permissions."""
    ww = [l.strip() for l in worldwrite_out.split('\n') if l.strip()]
    if ww:
        for d in ww[:5]:
            state.add_finding("MEDIUM", f"World-writable dir: {d}",
                f"Directory {d} is writable by any user on the system and does NOT have the sticky bit set. "
                "Without the sticky bit, any user can delete or rename files created by other users in this directory. "
                "An attacker could replace legitimate scripts or data files with malicious versions. The sticky bit "
                "(chmod +t) ensures only file owners can delete their own files.",
                f"sudo chmod +t {d}", f"sudo chmod -t {d}", cis_ref="CIS 6.1.10")
    tmp_ok = True
    for line in tmp_out.split('\n'):
        if '/tmp' in line and not line.startswith('1777'):
            tmp_ok = False
            state.add_finding("HIGH", "/tmp missing sticky bit",
                f"{line}. The /tmp directory is world-writable by design, but MUST have the sticky bit (1777) set. "
                "Without it, any user can delete or replace other users' temporary files — enabling symlink attacks "
                "where an attacker replaces a temp file with a symlink to a sensitive file (like /etc/shadow), causing "
                "a privileged process to overwrite it.",
                "sudo chmod 1777 /tmp", cis_ref="CIS 1.1.2")
    state.data['filesystem'] = {"world_writable": ww, "tmp_ok": tmp_ok}


def _parse_docker(state, docker_out):
    """Parse Docker containers."""
    containers = []
    issues = []
    if 'DOCKER_NONE' in docker_out:
        state.data['docker'] = {"running": [], "issues": []}
        return
    for line in docker_out.split('\n'):
        if not line.strip(): continue
        containers.append(line.strip())
    state.data['docker'] = {"running": containers, "issues": issues}
    if containers:
        state.log(f"✓ Docker: {len(containers)} containers")


def _parse_cron(state, crontabs_out, user_cron):
    """Parse all cron jobs."""
    jobs = []
    suspicious_cron = ['curl', 'wget', 'nc ', 'bash -i', '/dev/tcp', 'base64']
    for line in crontabs_out.split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('---'): continue
        if line.startswith('SHELL=') or line.startswith('PATH=') or line.startswith('MAILTO='): continue
        jobs.append({"source": "system", "line": line})
        for s in suspicious_cron:
            if s in line.lower():
                state.add_finding("CRITICAL", f"Suspicious cron job",
                    f"Scheduled task: {line[:80]}. This cron job uses commands commonly associated with post-exploitation "
                    "activity (curl/wget to download payloads, nc/bash -i for reverse shells, base64 to obfuscate "
                    "malicious commands, /dev/tcp for covert channels). Attackers install persistent cron jobs to "
                    "maintain access even after reboots or password changes. Review this job immediately and check "
                    "when it was added.")
                break
    if user_cron:
        for line in user_cron.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                jobs.append({"source": "user", "line": line})
    state.data['cron'] = {"jobs": jobs}
    state.log(f"✓ Cron: {len(jobs)} scheduled jobs")


def _parse_password_policy(state, policy_out):
    """Parse login.defs password policy."""
    policy = {}
    for line in policy_out.split('\n'):
        m = re.match(r'(\w+)\s+(\S+)', line)
        if m: policy[m.group(1)] = m.group(2)
    try:
        max_days = int(policy.get('PASS_MAX_DAYS', '99999'))
        if max_days > 365:
            state.add_finding("LOW", "Password expiry > 365 days",
                f"PASS_MAX_DAYS = {max_days}. Passwords never expire or have very long lifetimes. If a password is "
                "compromised (via phishing, data breach, or shoulder surfing), the attacker retains access indefinitely. "
                "Regular password rotation limits the window of exposure from a compromised credential. Industry "
                "standard is 90 days, though NIST now emphasizes password complexity over rotation.",
                "sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs",
                f"sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   {max_days}/' /etc/login.defs",
                cis_ref="CIS 5.5.1.1")
    except: pass
    if policy.get('ENCRYPT_METHOD', '').upper() not in ('SHA512', 'YESCRYPT', ''):
        state.add_finding("LOW", f"Weak password hash: {policy.get('ENCRYPT_METHOD', '?')}",
            f"Passwords are hashed with {policy.get('ENCRYPT_METHOD', '?')} instead of SHA512 or YESCRYPT. "
            "Weaker hash algorithms (like MD5 or DES) can be cracked orders of magnitude faster using GPU-based "
            "tools like hashcat. If an attacker obtains /etc/shadow, weak hashes mean passwords are recovered in "
            "seconds instead of years.",
            "sudo sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs",
            cis_ref="CIS 5.5.4")
    state.data['password_policy'] = policy


def _parse_dns(state, dns_out):
    """Parse DNS configuration."""
    resolvers = re.findall(r'nameserver\s+(\S+)', dns_out)
    state.data['dns'] = {"resolvers": resolvers, "raw": dns_out}


def _parse_audit(state, audit_out):
    """Parse auditd status."""
    active = 'AUDITD_INACTIVE' not in audit_out and audit_out.strip()
    rules = len([l for l in audit_out.split('\n') if l.strip() and not l.startswith('No rules')])
    if not active:
        state.add_finding("MEDIUM", "auditd not active",
            "The Linux Audit daemon is not running. Without audit logging, there is no record of who accessed what "
            "files, who ran privileged commands, or what system calls were made. After a breach, audit logs are "
            "essential for forensic investigation — determining what the attacker did, what data was accessed, and "
            "how they got in. Many compliance frameworks (SOC 2, PCI-DSS, HIPAA) require audit logging.",
            "sudo apt-get update; sudo apt-get install auditd -y && sudo systemctl enable --now auditd",
            cis_ref="CIS 4.1.1.1")
    state.data['audit'] = {"active": active, "rules": rules, "raw": audit_out.strip()[:500]}


def _parse_apparmor(state, apparmor_out):
    """Parse AppArmor/SELinux mandatory access control status."""
    active = 'APPARMOR_INACTIVE' not in apparmor_out and apparmor_out.strip()
    enforced = len(re.findall(r'enforce', apparmor_out, re.IGNORECASE))
    complain = len(re.findall(r'complain', apparmor_out, re.IGNORECASE))
    if not active:
        state.add_finding("MEDIUM", "AppArmor/SELinux not active",
            "No Mandatory Access Control (MAC) system is active. AppArmor/SELinux confines each program to a minimum "
            "set of permissions — even if a web server is compromised, the attacker cannot read /etc/shadow, write to "
            "/etc/cron.d, or access other services' data. Without MAC, a compromised process has full access to "
            "everything the running user can touch, making lateral movement trivial.",
            "sudo apt-get update; sudo apt-get install apparmor apparmor-utils -y && sudo systemctl enable --now apparmor",
            cis_ref="CIS 1.6.1.1")
    elif complain > 0:
        state.add_finding("LOW", f"AppArmor: {complain} profiles in complain mode",
            f"{complain} AppArmor profiles are in 'complain' mode, which logs policy violations but does NOT block them. "
            "This means confined applications can still perform restricted actions — the protection is monitoring-only. "
            "Switch profiles to 'enforce' mode to actually block unauthorized access attempts.",
            cis_ref="CIS 1.6.1.3")
    state.data['apparmor'] = {"active": active, "enforced": enforced, "complain": complain}


def _parse_sudoers(state, sudoers_out):
    """Parse sudoers for dangerous configurations."""
    issues = []
    dangerous_cmds = ['/bin/bash', '/bin/sh', '/usr/bin/env', '/usr/bin/python',
                      '/usr/bin/perl', '/usr/bin/ruby', '/usr/bin/vim', '/usr/bin/find']
    for line in sudoers_out.split('\n'):
        line = line.strip()
        if not line: continue
        if 'NOPASSWD' in line and 'ALL' in line:
            issues.append(f"NOPASSWD ALL: {line[:80]}")
            state.add_finding("HIGH", "Sudoers: NOPASSWD ALL detected",
                f"Sudoers entry: {line[:80]}. This allows a user to run ANY command as root without entering a "
                "password. If this user account is compromised (weak password, stolen SSH key, application vulnerability), "
                "the attacker immediately has full root access with no additional barrier. NOPASSWD should only be "
                "granted for specific, limited commands — never for ALL.",
                cis_ref="CIS 5.3")
        for dc in dangerous_cmds:
            if 'NOPASSWD' in line and dc in line:
                bin_name = os.path.basename(dc)
                issues.append(f"NOPASSWD {dc}: {line[:80]}")
                state.add_finding("HIGH", f"Sudoers: NOPASSWD on {dc}",
                    f"Sudoers grants password-free root access to {dc}. Tools like {bin_name} can trivially escalate "
                    "to a root shell (e.g., 'sudo vim -c \":!bash\"' or 'sudo find / -exec /bin/bash \\;'). "
                    "See GTFOBins for documented escalation paths. Any user who can run these commands without a "
                    "password effectively has unrestricted root access.",
                    cis_ref="CIS 5.3")
                break
    state.data['sudoers'] = {"issues": issues}


# ═══════════════════════════════════════════════════
#  FLASK ROUTES
# ═══════════════════════════════════════════════════
@app.route('/')
def index():
    from flask import make_response
    resp = make_response(HTML_PAGE)
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp

@app.route('/api/state')
def api_state():
    return jsonify(STATE.to_dict())

@app.route('/api/config', methods=['GET'])
def api_get_config():
    """Return saved config including decrypted passwords for pre-fill.
    Safe because AEGIS runs on localhost only — passwords never leave the machine."""
    cfg = load_config()
    result = {}
    for k, v in cfg.items():
        if k.endswith('_enc') or k.endswith('_fernet'):
            continue
        else:
            result[k] = v
    return jsonify(result)

@app.route('/api/connect', methods=['POST'])
def api_connect():
    """Connect to server with provided credentials."""
    global SSH_CONN
    data = request.json
    host = data.get('host', '').strip()
    user = data.get('user', '').strip()
    auth_mode = data.get('auth_mode', 'key')
    key_file = data.get('key_file', '').strip() or None
    sudo_pass = data.get('sudo_pass', '') or None
    ssh_pass = data.get('ssh_pass', '') or None
    save = data.get('save_config', False)
    server_role = data.get('server_role', 'general')
    custom_ports = data.get('custom_expected_ports', [])
    custom_services = data.get('custom_expected_services', [])
    custom_ids = data.get('custom_ids', [])

    if not host or not user:
        return jsonify({"error": "Host and username required"}), 400

    # Build SSH connection (clean up old one first)
    if SSH_CONN:
        try: SSH_CONN.cleanup()
        except: pass
    SSH_CONN = SSH(host, user, key_file=key_file if auth_mode == 'key' else None,
                   sudo_pass=sudo_pass, ssh_pass=ssh_pass if auth_mode == 'password' else None)

    # Save config if requested
    if save:
        cfg = {
            'host': host, 'user': user, 'auth_mode': auth_mode,
            'key_file': key_file or '', 'sudo_pass': sudo_pass or '',
            'ssh_pass': ssh_pass or '',
            'port': data.get('port', '5000'), 'server_role': server_role,
        }
        if server_role == 'custom':
            cfg['custom_ids'] = custom_ids
            cfg['custom_expected_ports'] = custom_ports
            cfg['custom_expected_services'] = custom_services
        save_config(cfg)

    # Start scan immediately (prevent duplicates)
    if STATE.scanning:
        _cleanup_subprocesses()
        STATE.scanning = False
    STATE.__init__()
    STATE.server_role = server_role
    if server_role == 'custom':
        STATE.custom_expected_ports = set(str(p) for p in custom_ports)
        STATE.custom_expected_services = set(custom_services)
    SSH_CONN._debug_lines = []  # Clear any stale debug lines
    t = threading.Thread(target=run_full_scan, args=(SSH_CONN, STATE), daemon=True)
    t.start()
    return jsonify({"status": "scanning"})

@app.route('/api/scan', methods=['POST'])
def api_scan():
    if not SSH_CONN:
        return jsonify({"error": "Not connected"}), 400
    if STATE.scanning:
        return jsonify({"error": "Scan already running"}), 409
    # Kill lingering command subprocesses but NOT the control master
    with _subprocess_lock:
        for proc in list(_active_subprocesses):
            if SSH_CONN and proc == SSH_CONN._control_proc:
                continue  # Keep the multiplexed connection alive
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except:
                try: proc.kill()
                except: pass
            _active_subprocesses.remove(proc)
    # Reset sudo mode detection so it re-probes on each scan
    SSH_CONN._sudo_mode = None
    SSH_CONN._debug_lines = []  # Clear stale debug from previous scan
    role = STATE.server_role
    cp = STATE.custom_expected_ports.copy()
    cs = STATE.custom_expected_services.copy()
    STATE.__init__()
    STATE.server_role = role
    STATE.custom_expected_ports = cp
    STATE.custom_expected_services = cs
    t = threading.Thread(target=run_full_scan, args=(SSH_CONN, STATE), daemon=True)
    t.start()
    return jsonify({"status": "started"})

@app.route('/api/set-role', methods=['POST'])
def api_set_role():
    data = request.json
    role = data.get('role', 'general')
    if role == 'custom':
        STATE.server_role = 'custom'
        STATE.custom_expected_ports = set(str(p) for p in data.get('custom_expected_ports', []))
        STATE.custom_expected_services = set(data.get('custom_expected_services', []))
        return jsonify({"status": "ok", "role": role, "label": "Custom"})
    if role not in SERVER_ROLES:
        return jsonify({"error": f"Unknown role: {role}"}), 400
    STATE.server_role = role
    return jsonify({"status": "ok", "role": role, "label": SERVER_ROLES[role]['label']})

@app.route('/api/roles')
def api_roles():
    return jsonify({k: {"label": v['label'], "desc": v['desc'],
                         "expected_ports": sorted(v['expected_ports']),
                         "expected_services": sorted(v.get('expected_services', set()))}
                    for k, v in SERVER_ROLES.items()})

@app.route('/api/scan-history')
def api_scan_history():
    try:
        HISTORY_DIR.mkdir(parents=True, exist_ok=True)
        scans = sorted(HISTORY_DIR.glob("scan_*.json"), reverse=True)
        history = []
        for s in scans[:20]:
            try: history.append(json.loads(s.read_text()))
            except: pass
        return jsonify({"history": history})
    except:
        return jsonify({"history": []})

@app.route('/api/debug-cmd', methods=['POST'])
def api_debug_cmd():
    """Run a single command via sudo and return raw output for debugging."""
    if not SSH_CONN:
        return jsonify({"error": "Not connected"})
    cmd = request.json.get('cmd', 'echo test')
    out, code = SSH_CONN.sudo(cmd)
    return jsonify({"output": out[:2000], "code": code})

_fix_in_progress = set()

@app.route('/api/fix', methods=['POST'])
def api_fix():
    data = request.json
    fid = data.get('id')
    f = next((x for x in STATE.findings if x['id'] == fid), None)
    if not SSH_CONN:
        STATE.log("✗ Fix failed: SSH not connected")
        return jsonify({"success": False, "output": "Not connected to server"})
    if not f or not f.get('fix_cmd') or f.get('fixed'):
        reason = 'already fixed' if f and f.get('fixed') else 'no fix command' if f else 'finding not found'
        STATE.log(f"✗ Fix skipped: {reason}")
        return jsonify({"success": False})
    if fid in _fix_in_progress:
        STATE.log(f"⚠ Fix already in progress: {f['title']}")
        return jsonify({"success": False, "output": "Fix already in progress"})
    _fix_in_progress.add(fid)
    try:
        cmd = _strip_sudo(f['fix_cmd'])
        STATE.log(f"▶ Applying fix: {f['title']}")
        # SAFETY: Any UFW command that could lock out SSH — ensure port 22 is allowed first
        if 'ufw' in cmd and ('enable' in cmd or 'default deny' in cmd):
            SSH_CONN.sudo("ufw allow 22/tcp", timeout=30)
        # For apt commands: fix any interrupted dpkg state first, increase timeout
        is_apt = any(k in cmd for k in ('apt ', 'apt-get ', 'dpkg-reconfigure'))
        if is_apt:
            SSH_CONN.sudo("dpkg --configure -a", timeout=30)
        out, code = SSH_CONN.sudo(cmd, timeout=300 if is_apt else 90)
        success = code == 0
        # For apt commands, check output for success indicators even with non-zero exit
        if not success and is_apt:
            apt_ok = any(s in out.lower() for s in ['is already the newest version', 'newly installed', '0 upgraded, 0 newly installed'])
            if apt_ok:
                success = True
                STATE.log(f"⚠ Fix returned code {code} but package action succeeded")
        if success:
            f['fixed'] = True
            STATE.add_action(f"Fixed: {f['title']}", f['fix_cmd'], f.get('undo_cmd'))
            STATE.log(f"✓ Fix applied: {f['title']}")
        else:
            STATE.log(f"✗ Fix FAILED (code {code}): {f['title']} → {out[:100]}")
    finally:
        _fix_in_progress.discard(fid)
    return jsonify({"success": success, "output": out[:200]})

@app.route('/api/fix-all', methods=['POST'])
def api_fix_all():
    fixed = 0
    # SAFETY: Pre-allow SSH before any batch fixes touch the firewall
    has_fw_fix = any('ufw' in (f.get('fix_cmd') or '') and ('enable' in (f.get('fix_cmd') or '') or 'default deny' in (f.get('fix_cmd') or ''))
                     for f in STATE.findings if f.get('fix_cmd') and not f.get('fixed'))
    if has_fw_fix:
        SSH_CONN.sudo("ufw allow 22/tcp", timeout=30)
    # Pre-fix any interrupted dpkg state if any fixes involve apt
    has_apt = any(any(k in (f.get('fix_cmd') or '') for k in ('apt ', 'apt-get ', 'dpkg-reconfigure'))
                  for f in STATE.findings if f.get('fix_cmd') and not f.get('fixed'))
    if has_apt:
        SSH_CONN.sudo("env DEBIAN_FRONTEND=noninteractive dpkg --configure -a", timeout=30)
    for f in STATE.findings:
        if f.get('fix_cmd') and not f.get('fixed'):
            cmd = _strip_sudo(f['fix_cmd'])
            is_apt = any(k in cmd for k in ('apt ', 'apt-get ', 'dpkg-reconfigure'))
            out, code = SSH_CONN.sudo(cmd, timeout=300 if is_apt else 90)
            success = code == 0
            if not success and is_apt:
                if any(s in out.lower() for s in ['is already the newest version', 'newly installed']):
                    success = True
            if success:
                f['fixed'] = True; fixed += 1
                STATE.add_action(f"Fixed: {f['title']}", f['fix_cmd'], f.get('undo_cmd'))
                STATE.log(f"✓ Fix applied: {f['title']}")
            else:
                STATE.log(f"✗ Fix FAILED (code {code}): {f['title']} → {out[:80]}")
    return jsonify({"fixed": fixed})

@app.route('/api/block-ip', methods=['POST'])
def api_block_ip():
    ip = request.json.get('ip', '').strip()
    if not ip or not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return jsonify({"success": False, "error": "Invalid IP address"})
    if not SSH_CONN:
        return jsonify({"success": False, "error": "Not connected"})
    out, code = SSH_CONN.sudo(f"ufw insert 1 deny from {ip}")
    success = code == 0 or "Rule inserted" in out or "Skipping" in out
    if success:
        STATE.add_action(f"Blocked {ip}", f"sudo ufw insert 1 deny from {ip}", f"sudo ufw delete deny from {ip}")
        # Update attacker state so UI refreshes correctly
        for a in STATE.data.get('logs', {}).get('attackers', []):
            if a['ip'] == ip:
                a['blocked'] = True
    return jsonify({"success": success, "output": out[:200]})

@app.route('/api/block-attackers', methods=['POST'])
def api_block_attackers():
    attackers = STATE.data.get('logs', {}).get('attackers', [])
    unblocked = [a for a in attackers if not a['banned'] and not a['blocked']][:10]
    blocked = 0
    for a in unblocked:
        out, code = SSH_CONN.sudo(f"ufw insert 1 deny from {a['ip']}")
        if code == 0 or "Rule inserted" in out:
            blocked += 1; a['blocked'] = True
            STATE.add_action(f"Blocked {a['ip']} ({a['count']} attempts)", f"sudo ufw insert 1 deny from {a['ip']}", f"sudo ufw delete deny from {a['ip']}")
    return jsonify({"blocked": blocked})

@app.route('/api/undo', methods=['POST'])
def api_undo():
    aid = request.json.get('id')
    a = next((x for x in STATE.actions if x['id'] == aid), None)
    if not a or not a.get('undo_cmd') or a.get('undone'):
        return jsonify({"success": False})
    out, code = SSH_CONN.sudo(a['undo_cmd'])
    if code == 0: a['undone'] = True
    return jsonify({"success": code == 0})

@app.route('/api/harden-f2b', methods=['POST'])
def api_harden_f2b():
    """Apply strict fail2ban config: 24h ban, 3 retries, escalating bans."""
    if not SSH_CONN:
        return jsonify({"success": False, "error": "Not connected"})
    jail_conf = """[DEFAULT]
bantime = 86400
findtime = 3600
maxretry = 3
bantime.increment = true
bantime.factor = 2
bantime.maxtime = 604800

[sshd]
enabled = true
"""
    escaped = jail_conf.replace("'", "'\\''")
    cmd = f"mkdir -p /etc/fail2ban && echo '{escaped}' > /etc/fail2ban/jail.local && systemctl restart fail2ban"
    out, code = SSH_CONN.sudo(cmd)
    success = code == 0
    if success:
        STATE.add_action("Hardened fail2ban: 24h ban, 3 retries, escalating",
            "Wrote /etc/fail2ban/jail.local",
            "sudo rm -f /etc/fail2ban/jail.local && sudo systemctl restart fail2ban")
        # Mark the finding as fixed
        for f in STATE.findings:
            if 'fail2ban config' in f.get('title', '').lower():
                f['fixed'] = True
    return jsonify({"success": success, "output": out[:300]})

@app.route('/api/kill-process', methods=['POST'])
def api_kill_process():
    """Kill a process by PID."""
    pid = request.json.get('pid')
    if not pid or not SSH_CONN: return jsonify({"success": False})
    out, code = SSH_CONN.sudo(f"kill -9 {pid}")
    success = code == 0
    if success:
        STATE.add_action(f"Killed PID {pid}", f"sudo kill -9 {pid}")
    return jsonify({"success": success, "output": out[:200]})

@app.route('/api/disable-service', methods=['POST'])
def api_disable_service():
    """Disable and stop a systemd service."""
    svc = request.json.get('service', '').strip()
    if not svc or not SSH_CONN: return jsonify({"success": False})
    # Sanitize — only allow alphanumeric, dash, underscore, dot
    if not re.match(r'^[\w\-\.]+$', svc):
        return jsonify({"success": False, "error": "Invalid service name"})
    out, code = SSH_CONN.sudo(f"systemctl disable {svc} && systemctl stop {svc}")
    success = code == 0
    if success:
        STATE.add_action(f"Disabled service: {svc}",
            f"sudo systemctl disable {svc} && sudo systemctl stop {svc}",
            f"sudo systemctl enable {svc} && sudo systemctl start {svc}")
    return jsonify({"success": success, "output": out[:200]})

@app.route('/api/remove-cron', methods=['POST'])
def api_remove_cron():
    """Comment out a cron job line."""
    line = request.json.get('line', '').strip()
    source = request.json.get('source', 'user')
    if not line or not SSH_CONN: return jsonify({"success": False})
    escaped = line.replace("'", "'\\''").replace("/", "\\/")
    if source == 'user':
        out, code = SSH_CONN.run(f"crontab -l 2>/dev/null | sed 's/^{escaped}$/# DISABLED: {escaped}/' | crontab -")
    else:
        out, code = SSH_CONN.sudo(f"sed -i 's|^{escaped}$|# DISABLED: {escaped}|' /etc/crontab")
    success = code == 0
    if success:
        STATE.add_action(f"Disabled cron: {line[:60]}", f"Commented out cron line")
    return jsonify({"success": success, "output": out[:200]})


# ═══════════════════════════════════════════════════
#  UFW & NGINX MANAGEMENT APIs
# ═══════════════════════════════════════════════════

@app.route('/api/manage/ufw/status')
def api_ufw_status():
    """Get detailed UFW status including numbered rules."""
    if not SSH_CONN: return jsonify({"error": "Not connected"})
    out, code = SSH_CONN.sudo("ufw status numbered verbose 2>/dev/null || echo UFW_NOT_INSTALLED")
    if 'UFW_NOT_INSTALLED' in out or 'command not found' in out.lower():
        return jsonify({"installed": False, "active": False, "rules": [], "default_in": "unknown", "default_out": "unknown"})
    active = 'status: active' in out.lower()
    # Parse defaults
    di = re.search(r'Default:\s*(\w+)\s*\(incoming\)', out)
    do = re.search(r'Default:\s*\w+\s*\(incoming\),\s*(\w+)\s*\(outgoing\)', out)
    # Parse numbered rules
    rules = []
    for m in re.finditer(r'^\[\s*(\d+)\]\s+(.+)$', out, re.MULTILINE):
        rules.append({"num": int(m.group(1)), "rule": m.group(2).strip()})
    return jsonify({"installed": True, "active": active, "rules": rules,
                     "default_in": di.group(1).lower() if di else "unknown",
                     "default_out": do.group(1).lower() if do else "unknown",
                     "raw": out[:2000]})

@app.route('/api/manage/ufw/install', methods=['POST'])
def api_ufw_install():
    if not SSH_CONN: return jsonify({"error": "Not connected"})
    STATE.log("▶ Installing UFW...")
    SSH_CONN.sudo("dpkg --configure -a", timeout=30)
    SSH_CONN.sudo("apt-get update", timeout=60)
    out, code = SSH_CONN.sudo("env DEBIAN_FRONTEND=noninteractive apt-get install ufw -y", timeout=300)
    ok = code == 0 or 'is already the newest version' in out.lower() or 'newly installed' in out.lower()
    STATE.log(f"{'✓' if ok else '✗'} UFW install: {'success' if ok else 'failed — ' + out.strip()[:120]}")
    return jsonify({"success": ok, "output": out[:500]})

@app.route('/api/manage/ufw/enable', methods=['POST'])
def api_ufw_enable():
    if not SSH_CONN: return jsonify({"error": "Not connected"})
    # Always allow SSH first to prevent lockout
    SSH_CONN.sudo("ufw allow 22/tcp", timeout=30)
    STATE.log("▶ Enabling UFW (SSH pre-allowed)...")
    out, code = SSH_CONN.sudo("ufw --force enable", timeout=15)
    STATE.log(f"{'✓' if code==0 else '✗'} UFW enable: {out.strip()[:80]}")
    return jsonify({"success": code == 0, "output": out[:500]})

@app.route('/api/manage/ufw/disable', methods=['POST'])
def api_ufw_disable():
    if not SSH_CONN: return jsonify({"error": "Not connected"})
    STATE.log("▶ Disabling UFW...")
    out, code = SSH_CONN.sudo("ufw --force disable", timeout=15)
    STATE.log(f"{'✓' if code==0 else '✗'} UFW disable: {out.strip()[:80]}")
    return jsonify({"success": code == 0, "output": out[:500]})

@app.route('/api/manage/ufw/default', methods=['POST'])
def api_ufw_default():
    if not SSH_CONN: return jsonify({"error": "Not connected"})
    direction = request.json.get('direction', 'incoming')  # incoming or outgoing
    policy = request.json.get('policy', 'deny')  # allow, deny, reject
    if direction not in ('incoming', 'outgoing') or policy not in ('allow', 'deny', 'reject'):
        return jsonify({"error": "Invalid direction/policy"})
    # Safety: if setting incoming to deny, ensure SSH is allowed
    if direction == 'incoming' and policy in ('deny', 'reject'):
        SSH_CONN.sudo("ufw allow 22/tcp", timeout=30)
    STATE.log(f"▶ Setting UFW default {direction} to {policy}...")
    out, code = SSH_CONN.sudo(f"ufw default {policy} {direction}", timeout=30)
    STATE.log(f"{'✓' if code==0 else '✗'} UFW default {direction} → {policy}")
    return jsonify({"success": code == 0, "output": out[:500]})

@app.route('/api/manage/ufw/add-rule', methods=['POST'])
def api_ufw_add_rule():
    if not SSH_CONN: return jsonify({"error": "Not connected"})
    data = request.json
    port = str(data.get('port', '')).strip()
    proto = data.get('proto', 'tcp')  # tcp, udp, or both
    action = data.get('action', 'allow')  # allow, deny, reject, limit
    from_ip = data.get('from_ip', '').strip()
    comment = data.get('comment', '').strip()

    if not port or not re.match(r'^\d+(?::\d+)?$', port):
        return jsonify({"error": "Invalid port (use number or range like 8000:8100)"})
    if action not in ('allow', 'deny', 'reject', 'limit'):
        return jsonify({"error": "Invalid action"})
    if proto not in ('tcp', 'udp', 'both'):
        return jsonify({"error": "Invalid protocol"})

    # Build UFW command
    proto_part = f"/{proto}" if proto != 'both' else ""
    if from_ip and re.match(r'^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$', from_ip):
        cmd = f"ufw {action} from {from_ip} to any port {port}{proto_part}"
    else:
        cmd = f"ufw {action} {port}{proto_part}"
    if comment:
        cmd += f" comment '{comment}'"

    STATE.log(f"▶ UFW: {cmd}")
    out, code = SSH_CONN.sudo(cmd, timeout=30)
    STATE.log(f"{'✓' if code==0 else '✗'} {cmd}: {out.strip()[:80]}")
    return jsonify({"success": code == 0, "output": out[:500], "cmd": cmd})

@app.route('/api/manage/ufw/delete-rule', methods=['POST'])
def api_ufw_delete_rule():
    if not SSH_CONN: return jsonify({"error": "Not connected"})
    rule_num = request.json.get('num')
    if not rule_num or not str(rule_num).isdigit():
        return jsonify({"error": "Invalid rule number"})
    # Safety: don't delete SSH rules without warning (handled in frontend)
    STATE.log(f"▶ UFW: deleting rule #{rule_num}...")
    out, code = SSH_CONN.sudo(f"echo y | ufw delete {rule_num}", timeout=30)
    STATE.log(f"{'✓' if code==0 else '✗'} Rule #{rule_num} deleted")
    return jsonify({"success": code == 0, "output": out[:500]})

@app.route('/api/manage/ufw/block-ip', methods=['POST'])
def api_ufw_block_ip():
    if not SSH_CONN: return jsonify({"error": "Not connected"})
    ip = request.json.get('ip', '').strip()
    if not ip or not re.match(r'^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$', ip):
        return jsonify({"error": "Invalid IP/CIDR"})
    STATE.log(f"▶ UFW: blocking {ip}...")
    out, code = SSH_CONN.sudo(f"ufw deny from {ip}", timeout=30)
    STATE.log(f"{'✓' if code==0 else '✗'} Blocked {ip}")
    return jsonify({"success": code == 0, "output": out[:500]})

# ─── Fail2ban Management ───

@app.route('/api/manage/f2b/status')
def api_f2b_status():
    """Get fail2ban status including banned IPs and whitelist."""
    if not SSH_CONN: return jsonify({"error": "Not connected"})
    # Use output-based check — increase timeout for Windows SSH handshake
    check_out, check_code = SSH_CONN.sudo("which fail2ban-client", timeout=30)
    STATE.log(f"[f2b] which: code={check_code} out='{check_out.strip()[:80]}'")
    installed = 'fail2ban' in check_out.lower()
    if not installed and '[TIMEOUT]' not in check_out:
        dpkg_out, dpkg_code = SSH_CONN.sudo("dpkg -l fail2ban", timeout=30)
        STATE.log(f"[f2b] dpkg: code={dpkg_code} out='{dpkg_out.strip()[:80]}'")
        # Look for 'ii  fail2ban' anywhere in output, not just first 20 chars
        installed = bool(re.search(r'^ii\s+fail2ban', dpkg_out, re.MULTILINE))
    if not installed:
        STATE.log("[f2b] Not installed")
        return jsonify({"installed": False})
    status_out, _ = SSH_CONN.sudo("fail2ban-client status sshd 2>&1", timeout=30)
    running = 'Currently failed' in status_out or 'Banned IP list' in status_out
    banned = re.findall(r'\d+\.\d+\.\d+\.\d+', status_out.split('Banned IP list:')[-1] if 'Banned IP list:' in status_out else '')
    bt_out, _ = SSH_CONN.sudo("fail2ban-client get sshd bantime", timeout=30)
    mr_out, _ = SSH_CONN.sudo("fail2ban-client get sshd maxretry", timeout=30)
    ft_out, _ = SSH_CONN.sudo("fail2ban-client get sshd findtime", timeout=30)
    conf = [l.strip() for l in (bt_out + '\n' + mr_out + '\n' + ft_out).strip().split('\n') if l.strip() and not l.strip().startswith('[')]
    wl_out, _ = SSH_CONN.sudo("fail2ban-client get sshd ignoreip", timeout=30)
    whitelist = re.findall(r'[\d./]+', wl_out)
    sshd_out, _ = SSH_CONN.run("grep -E '^(MaxStartups|MaxSessions|LoginGraceTime)' /etc/ssh/sshd_config 2>/dev/null", timeout=30)
    return jsonify({"installed": True, "running": running, "banned": banned,
                     "whitelist": whitelist, "config": conf, "sshd_settings": sshd_out.strip() or "defaults"})

@app.route('/api/manage/f2b/unban', methods=['POST'])
def api_f2b_unban():
    if not SSH_CONN: return jsonify({"error": "Not connected"})
    ip = request.json.get('ip', '').strip()
    if not ip or not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
        return jsonify({"error": "Invalid IP"})
    STATE.log(f"▶ Unbanning {ip} from fail2ban...")
    out, code = SSH_CONN.sudo(f"fail2ban-client set sshd unbanip {ip}", timeout=30)
    STATE.log(f"{'✓' if code==0 else '✗'} Unban {ip}: {out.strip()[:80]}")
    return jsonify({"success": code == 0})

@app.route('/api/manage/f2b/whitelist', methods=['POST'])
def api_f2b_whitelist():
    if not SSH_CONN: return jsonify({"error": "Not connected"})
    ip = request.json.get('ip', '').strip()
    if not ip or not re.match(r'^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$', ip):
        return jsonify({"error": "Invalid IP/CIDR"})
    STATE.log(f"▶ Whitelisting {ip} in fail2ban...")
    # Add to runtime
    SSH_CONN.sudo(f"fail2ban-client set sshd addignoreip {ip}", timeout=30)
    # Add to persistent config
    out, code = SSH_CONN.sudo(
        f"grep -q 'ignoreip.*=.*{ip}' /etc/fail2ban/jail.local 2>/dev/null || "
        f"sed -i '/\\[sshd\\]/,/^\\[/{{ /ignoreip/s/$/ {ip}/; }}' /etc/fail2ban/jail.local 2>/dev/null || "
        f"echo -e '[sshd]\\nignoreip = 127.0.0.1/8 {ip}' >> /etc/fail2ban/jail.local",
        timeout=30)
    STATE.log(f"{'✓' if code==0 else '✗'} Whitelisted {ip}")
    return jsonify({"success": True})

@app.route('/api/manage/f2b/unban-all', methods=['POST'])
def api_f2b_unban_all():
    if not SSH_CONN: return jsonify({"error": "Not connected"})
    STATE.log("▶ Unbanning all IPs from fail2ban...")
    out, code = SSH_CONN.sudo("fail2ban-client unban --all", timeout=30)
    STATE.log(f"{'✓' if code==0 else '✗'} Unban all: {out.strip()[:80]}")
    return jsonify({"success": code == 0})

# ─── Nginx Management ───

@app.route('/api/manage/nginx/status')
def api_nginx_status():
    """Get nginx status, sites, and upstream config."""
    if not SSH_CONN: return jsonify({"error": "Not connected"})
    # Check installed — use output-based detection
    check_out, check_code = SSH_CONN.sudo("which nginx", timeout=30)
    STATE.log(f"[nginx] which: code={check_code} out='{check_out.strip()[:80]}'")
    installed = 'nginx' in check_out.lower() and '[TIMEOUT]' not in check_out
    if not installed and '[TIMEOUT]' not in check_out:
        dpkg_out, dpkg_code = SSH_CONN.sudo("dpkg -l nginx", timeout=30)
        STATE.log(f"[nginx] dpkg: code={dpkg_code} out='{dpkg_out.strip()[:80]}'")
        installed = bool(re.search(r'^ii\s+nginx', dpkg_out, re.MULTILINE))
    if not installed:
        STATE.log("[nginx] Not installed")
        return jsonify({"installed": False, "active": False, "sites": []})

    # Get version
    ver_out, _ = SSH_CONN.run("nginx -v 2>&1", timeout=30)
    version = ver_out.strip()

    # Get status
    status_out, _ = SSH_CONN.sudo("systemctl is-active nginx 2>/dev/null", timeout=30)
    active = 'active' in status_out.strip()

    # Get sites list and configs in one batch
    sites_cmd = """echo '===SITES_AVAILABLE==='
ls -1 /etc/nginx/sites-available/ 2>/dev/null || echo NONE
echo '===SITES_ENABLED==='
ls -1 /etc/nginx/sites-enabled/ 2>/dev/null || echo NONE
echo '===SITE_CONFIGS==='
for f in /etc/nginx/sites-available/*; do
  [ -f "$f" ] || continue
  echo "===SITE_$(basename $f)==="
  cat "$f" 2>/dev/null
done
echo '===TEST==='
nginx -t 2>&1 || echo 'NGINX_TEST_FAIL'"""
    out, code = SSH_CONN.sudo(sites_cmd, timeout=30)
    available = [s.strip() for s in section(out, 'SITES_AVAILABLE').strip().split('\n') if s.strip() and s.strip() != 'NONE']
    enabled = [s.strip() for s in section(out, 'SITES_ENABLED').strip().split('\n') if s.strip() and s.strip() != 'NONE']
    test_ok = 'NGINX_TEST_FAIL' not in section(out, 'TEST')

    # Parse each site config
    sites = []
    for name in available:
        site = {"name": name, "enabled": name in enabled, "listen": [], "server_name": "", "locations": [], "ssl": False}
        cfg = section(out, f'SITE_{name}')
        if cfg:
            for lm in re.finditer(r'listen\s+(.+?);', cfg):
                site['listen'].append(lm.group(1).strip())
            snm = re.search(r'server_name\s+(.+?);', cfg)
            if snm: site['server_name'] = snm.group(1).strip()
            for loc in re.finditer(r'location\s+(\S+)\s*\{([^}]*)\}', cfg, re.DOTALL):
                loc_info = {"path": loc.group(1), "type": "static"}
                body = loc.group(2)
                pp = re.search(r'proxy_pass\s+(\S+)', body)
                if pp: loc_info["type"] = "proxy"; loc_info["proxy_pass"] = pp.group(1).rstrip(';')
                root = re.search(r'root\s+(\S+)', body)
                if root: loc_info["root"] = root.group(1).rstrip(';')
                site['locations'].append(loc_info)
            site['ssl'] = 'ssl' in cfg.lower() and ('ssl_certificate' in cfg or '443 ssl' in cfg)
            site['raw_config'] = cfg
        sites.append(site)

    return jsonify({"installed": True, "active": active, "version": version, "sites": sites,
                     "test_ok": test_ok})

@app.route('/api/manage/nginx/install', methods=['POST'])
def api_nginx_install():
    if not SSH_CONN: return jsonify({"error": "Not connected"})
    STATE.log("▶ Installing nginx...")
    # Run apt-get update first, then install — as separate commands to avoid chain issues
    SSH_CONN.sudo("dpkg --configure -a", timeout=30)
    out1, _ = SSH_CONN.sudo("apt-get update", timeout=60)
    out, code = SSH_CONN.sudo("env DEBIAN_FRONTEND=noninteractive apt-get install nginx -y", timeout=300)
    ok = code == 0 or 'is already the newest version' in out.lower() or 'newly installed' in out.lower()
    if ok:
        SSH_CONN.sudo("systemctl enable --now nginx", timeout=30)
    STATE.log(f"{'✓' if ok else '✗'} Nginx install: {'success' if ok else 'failed — ' + out.strip()[:120]}")
    return jsonify({"success": ok, "output": out[:500]})

@app.route('/api/manage/nginx/toggle', methods=['POST'])
def api_nginx_toggle():
    if not SSH_CONN: return jsonify({"error": "Not connected"})
    action = request.json.get('action', 'start')  # start, stop, restart, reload
    if action not in ('start', 'stop', 'restart', 'reload'):
        return jsonify({"error": "Invalid action"})
    STATE.log(f"▶ Nginx {action}...")
    out, code = SSH_CONN.sudo(f"systemctl {action} nginx", timeout=30)
    STATE.log(f"{'✓' if code==0 else '✗'} Nginx {action}")
    return jsonify({"success": code == 0, "output": out[:500]})

@app.route('/api/manage/nginx/create-site', methods=['POST'])
def api_nginx_create_site():
    if not SSH_CONN: return jsonify({"error": "Not connected"})
    data = request.json
    name = re.sub(r'[^a-zA-Z0-9._-]', '', data.get('name', '').strip())
    if not name: return jsonify({"error": "Invalid site name"})

    site_type = data.get('type', 'proxy')  # proxy, static, redirect
    domain = data.get('domain', '_')
    listen_port = str(data.get('listen_port', '80'))
    proxy_target = data.get('proxy_target', '')  # e.g., http://127.0.0.1:3000
    root_path = data.get('root_path', '')  # e.g., /var/www/html
    redirect_url = data.get('redirect_url', '')
    enable_ssl = data.get('ssl', False)

    # Build nginx config
    lines = [f"server {{", f"    listen {listen_port};", f"    server_name {domain};", ""]

    if enable_ssl:
        lines.insert(2, f"    listen 443 ssl;")
        lines.extend([
            f"    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;",
            f"    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;",
            ""])

    if site_type == 'proxy' and proxy_target:
        lines.extend([
            "    location / {",
            f"        proxy_pass {proxy_target};",
            "        proxy_set_header Host $host;",
            "        proxy_set_header X-Real-IP $remote_addr;",
            "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
            "        proxy_set_header X-Forwarded-Proto $scheme;",
            "        proxy_http_version 1.1;",
            "        proxy_set_header Upgrade $http_upgrade;",
            "        proxy_set_header Connection \"upgrade\";",
            "    }",
        ])
    elif site_type == 'static' and root_path:
        lines.extend([
            f"    root {root_path};",
            "    index index.html index.htm;",
            "",
            "    location / {",
            "        try_files $uri $uri/ =404;",
            "    }",
        ])
    elif site_type == 'redirect' and redirect_url:
        lines.extend([
            "    location / {",
            f"        return 301 {redirect_url}$request_uri;",
            "    }",
        ])

    lines.append("}")
    config = '\n'.join(lines)

    import base64
    encoded = base64.b64encode(config.encode()).decode()
    cmd = (f"echo '{encoded}' | base64 -d | tee /etc/nginx/sites-available/{name} > /dev/null && "
           f"ln -sf /etc/nginx/sites-available/{name} /etc/nginx/sites-enabled/{name} && "
           f"nginx -t")

    STATE.log(f"▶ Creating nginx site: {name} ({site_type})...")
    out, code = SSH_CONN.sudo(cmd, timeout=30)
    if code == 0:
        SSH_CONN.sudo("systemctl reload nginx", timeout=30)
        STATE.log(f"✓ Site {name} created and enabled")
    else:
        STATE.log(f"✗ Site {name} failed nginx test: {out[:100]}")
    return jsonify({"success": code == 0, "output": out[:500], "config": config})

@app.route('/api/manage/nginx/toggle-site', methods=['POST'])
def api_nginx_toggle_site():
    if not SSH_CONN: return jsonify({"error": "Not connected"})
    name = re.sub(r'[^a-zA-Z0-9._-]', '', request.json.get('name', ''))
    enable = request.json.get('enable', True)
    if not name: return jsonify({"error": "Invalid site name"})

    if enable:
        cmd = f"ln -sf /etc/nginx/sites-available/{name} /etc/nginx/sites-enabled/{name} && nginx -t && systemctl reload nginx"
    else:
        cmd = f"rm -f /etc/nginx/sites-enabled/{name} && nginx -t && systemctl reload nginx"

    STATE.log(f"▶ {'Enabling' if enable else 'Disabling'} site {name}...")
    out, code = SSH_CONN.sudo(cmd, timeout=30)
    STATE.log(f"{'✓' if code==0 else '✗'} Site {name} {'enabled' if enable else 'disabled'}")
    return jsonify({"success": code == 0, "output": out[:500]})

@app.route('/api/manage/nginx/delete-site', methods=['POST'])
def api_nginx_delete_site():
    if not SSH_CONN: return jsonify({"error": "Not connected"})
    name = re.sub(r'[^a-zA-Z0-9._-]', '', request.json.get('name', ''))
    if not name: return jsonify({"error": "Invalid site name"})
    STATE.log(f"▶ Deleting site {name}...")
    out, code = SSH_CONN.sudo(f"rm -f /etc/nginx/sites-enabled/{name} /etc/nginx/sites-available/{name} && nginx -t && systemctl reload nginx", timeout=30)
    STATE.log(f"{'✓' if code==0 else '✗'} Site {name} deleted")
    return jsonify({"success": code == 0, "output": out[:500]})

@app.route('/api/manage/nginx/edit-site', methods=['POST'])
def api_nginx_edit_site():
    """Replace a site's config with new content."""
    if not SSH_CONN: return jsonify({"error": "Not connected"})
    name = re.sub(r'[^a-zA-Z0-9._-]', '', request.json.get('name', ''))
    config = request.json.get('config', '')
    if not name or not config: return jsonify({"error": "Missing name or config"})

    import base64
    encoded = base64.b64encode(config.encode()).decode()
    # Write config, test, reload
    cmd = (f"echo '{encoded}' | base64 -d | tee /etc/nginx/sites-available/{name} > /dev/null && nginx -t")
    STATE.log(f"▶ Updating site config: {name}...")
    out, code = SSH_CONN.sudo(cmd, timeout=30)
    if code == 0:
        SSH_CONN.sudo("systemctl reload nginx", timeout=30)
        STATE.log(f"✓ Site {name} config updated")
    else:
        STATE.log(f"✗ Config test failed: {out[:100]}")
    return jsonify({"success": code == 0, "output": out[:500]})

@app.route('/api/manage/nginx/get-site-config')
def api_nginx_get_site_config():
    if not SSH_CONN: return jsonify({"error": "Not connected"})
    name = re.sub(r'[^a-zA-Z0-9._-]', '', request.args.get('name', ''))
    if not name: return jsonify({"error": "Invalid site name"})
    out, code = SSH_CONN.sudo(f"cat /etc/nginx/sites-available/{name}", timeout=30)
    return jsonify({"config": out if code == 0 else "", "error": None if code == 0 else "File not found"})


# ═══════════════════════════════════════════════════
#  EXTERNAL SCAN ENGINE
# ═══════════════════════════════════════════════════
EXT_STATE = {"scanning": False, "progress": 0, "results": {}, "log": []}

def _ext_log(msg):
    EXT_STATE['log'].append({"ts": datetime.now().strftime("%H:%M:%S"), "msg": msg})
    print(f"  [{datetime.now().strftime('%H:%M:%S')}] [EXT] {msg}", flush=True)

def run_external_scan(host):
    """Run external exposure scan from local machine against public IP."""
    EXT_STATE['scanning'] = True
    EXT_STATE['progress'] = 0
    EXT_STATE['results'] = {}
    EXT_STATE['log'] = []
    results = EXT_STATE['results']

    _ext_log(f"▶ External scan of {host}")
    _ext_log("  This scans from YOUR machine — shows what an attacker sees")

    # ── 1. TCP Port Scan (common ports) ──
    EXT_STATE['progress'] = 5
    _ext_log("▶ Scanning common TCP ports...")
    common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                    993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379,
                    8080, 8443, 8888, 9090, 9200, 11211, 27017]
    open_ports = []
    closed_ports = []

    import socket
    for i, port in enumerate(common_ports):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            if result == 0:
                # Try banner grab
                banner = ""
                try:
                    sock.settimeout(2)
                    if port in (80, 8080, 8443, 443):
                        sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                    else:
                        sock.sendall(b"\r\n")
                    banner = sock.recv(256).decode('utf-8', errors='replace').strip()[:120]
                except: pass
                svc = _guess_service(port, banner)
                open_ports.append({"port": port, "service": svc, "banner": banner})
                _ext_log(f"  ✓ Port {port} OPEN ({svc})")
            else:
                closed_ports.append(port)
            sock.close()
        except:
            closed_ports.append(port)
        EXT_STATE['progress'] = 5 + int((i / len(common_ports)) * 30)

    results['open_ports'] = open_ports
    results['closed_ports'] = closed_ports
    results['total_scanned'] = len(common_ports)
    _ext_log(f"✓ Port scan: {len(open_ports)} open / {len(closed_ports)} closed")

    # Flag dangerous open ports
    dangerous_ports = {21: 'FTP', 23: 'Telnet', 25: 'SMTP', 110: 'POP3', 111: 'RPC',
                       135: 'MS-RPC', 139: 'NetBIOS', 445: 'SMB', 1433: 'MSSQL',
                       3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
                       6379: 'Redis', 9200: 'Elasticsearch', 11211: 'Memcached', 27017: 'MongoDB'}
    findings = []
    for p in open_ports:
        if p['port'] in dangerous_ports:
            findings.append({"sev": "HIGH", "title": f"Port {p['port']} ({dangerous_ports[p['port']]}) exposed externally",
                "detail": f"Banner: {p['banner'][:60]}" if p['banner'] else "Accessible from internet",
                "fix_cmd": f"sudo ufw deny {p['port']}/tcp",
                "undo_cmd": f"sudo ufw delete deny {p['port']}/tcp"})

    EXT_STATE['progress'] = 40

    # ── 2. HTTP Security Headers ──
    _ext_log("▶ Checking HTTP security headers...")
    http_results = {"available": False, "headers": {}, "missing": [], "server": "", "redirects_https": False}

    for scheme in ['https', 'http']:
        try:
            import urllib.request, urllib.error, ssl
            url = f"{scheme}://{host}/"
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={'User-Agent': 'AEGIS-Scanner/5.0'})
            resp = urllib.request.urlopen(req, timeout=30, context=ctx)
            http_results['available'] = True
            hdrs = dict(resp.headers)
            http_results['headers'] = hdrs
            http_results['server'] = hdrs.get('Server', '?')
            http_results['status'] = resp.status

            # Check security headers
            required = {
                'Strict-Transport-Security': 'HSTS not set',
                'X-Frame-Options': 'Clickjacking possible',
                'X-Content-Type-Options': 'MIME sniffing possible',
                'Content-Security-Policy': 'No CSP policy',
                'X-XSS-Protection': 'XSS protection not set',
                'Referrer-Policy': 'Referrer policy not set',
                'Permissions-Policy': 'Permissions policy not set',
            }
            for header, issue in required.items():
                found = any(k.lower() == header.lower() for k in hdrs)
                http_results.setdefault('checks', []).append({
                    "header": header, "present": found,
                    "value": next((v for k, v in hdrs.items() if k.lower() == header.lower()), None)
                })
                if not found:
                    http_results['missing'].append(header)
                    findings.append({"sev": "MEDIUM", "title": f"Missing header: {header}",
                        "detail": issue, "fix_cmd": None, "undo_cmd": None})

            # Server header info leak
            if http_results['server'] and http_results['server'] != '?':
                findings.append({"sev": "LOW", "title": f"Server header reveals: {http_results['server']}",
                    "detail": "Information disclosure", "fix_cmd": None, "undo_cmd": None})

            _ext_log(f"✓ HTTP ({scheme}): status {resp.status}, server={http_results['server']}, {len(http_results['missing'])} headers missing")
            break  # Got a response, don't try the other scheme
        except Exception as e:
            _ext_log(f"  {scheme}: {str(e)[:60]}")

    results['http'] = http_results
    EXT_STATE['progress'] = 55

    # ── 3. SSL/TLS Check ──
    _ext_log("▶ Checking SSL/TLS...")
    ssl_results = {"available": False}
    try:
        import ssl
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=30) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                ssl_results['available'] = True
                ssl_results['version'] = ssock.version()
                ssl_results['cipher'] = ssock.cipher()
                # Cert expiry
                import email.utils as eu
                not_after = cert.get('notAfter', '')
                if not_after:
                    from datetime import timezone
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days = (exp - datetime.now()).days
                    ssl_results['expires_days'] = days
                    ssl_results['expires'] = not_after
                    ssl_results['subject'] = dict(x[0] for x in cert.get('subject', []))
                    ssl_results['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                    ssl_results['san'] = [x[1] for x in cert.get('subjectAltName', [])]
                    if days < 30:
                        findings.append({"sev": "HIGH", "title": f"SSL cert expires in {days} days",
                            "detail": not_after, "fix_cmd": "sudo certbot renew", "undo_cmd": None})
                _ext_log(f"✓ SSL: {ssl_results['version']}, expires in {ssl_results.get('expires_days','?')} days")
    except Exception as e:
        _ext_log(f"  SSL: {str(e)[:60]}")

    # Test for weak TLS versions
    for ver_name, ver_const in [('TLSv1.0', ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None),
                                 ('TLSv1.1', ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None)]:
        if ver_const is None: continue
        try:
            ctx2 = ssl.SSLContext(ver_const)
            with socket.create_connection((host, 443), timeout=3) as s2:
                with ctx2.wrap_socket(s2, server_hostname=host) as ss2:
                    ssl_results[f'supports_{ver_name}'] = True
                    findings.append({"sev": "MEDIUM", "title": f"Server supports weak {ver_name}",
                        "detail": "Should be disabled", "fix_cmd": None, "undo_cmd": None})
                    _ext_log(f"  ⚠ Supports weak {ver_name}")
        except: pass

    results['ssl'] = ssl_results
    EXT_STATE['progress'] = 70

    # ── 4. DNS Checks ──
    _ext_log("▶ Checking DNS records...")
    dns_results = {}
    try:
        # Reverse DNS
        try:
            rdns = socket.gethostbyaddr(host)
            dns_results['reverse'] = rdns[0]
            _ext_log(f"  Reverse DNS: {rdns[0]}")
        except: dns_results['reverse'] = None

        # Forward lookup
        try:
            fwd = socket.getaddrinfo(host, None)
            dns_results['addresses'] = list(set(a[4][0] for a in fwd))
        except: dns_results['addresses'] = [host]
    except: pass
    results['dns'] = dns_results
    EXT_STATE['progress'] = 80

    # ── 5. SSH Banner ──
    _ext_log("▶ Checking SSH banner...")
    ssh_ext = {}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, 22))
        banner = s.recv(256).decode('utf-8', errors='replace').strip()
        s.close()
        ssh_ext['banner'] = banner
        ssh_ext['version'] = banner
        _ext_log(f"  SSH banner: {banner}")
        if banner:
            findings.append({"sev": "LOW", "title": f"SSH banner: {banner[:60]}",
                "detail": "Reveals software version", "fix_cmd": None, "undo_cmd": None})
    except Exception as e:
        ssh_ext['banner'] = None
        _ext_log(f"  SSH: {str(e)[:40]}")
    results['ssh_banner'] = ssh_ext
    EXT_STATE['progress'] = 90

    # ── 6. Scoring ──
    ext_score = 100
    for f in findings:
        w = {"CRITICAL": 20, "HIGH": 12, "MEDIUM": 5, "LOW": 2}.get(f['sev'], 0)
        ext_score -= w
    ext_score = max(0, ext_score)

    results['findings'] = findings
    results['score'] = ext_score

    _ext_log(f"═══ External scan complete — Score: {ext_score}/100 — {len(findings)} findings ═══")
    EXT_STATE['progress'] = 100
    EXT_STATE['scanning'] = False


def _guess_service(port, banner):
    """Guess service name from port number and banner."""
    known = {21:'FTP', 22:'SSH', 23:'Telnet', 25:'SMTP', 53:'DNS', 80:'HTTP', 110:'POP3',
             111:'RPC', 135:'MS-RPC', 139:'NetBIOS', 143:'IMAP', 443:'HTTPS', 445:'SMB',
             993:'IMAPS', 995:'POP3S', 1433:'MSSQL', 1521:'Oracle', 2049:'NFS',
             3306:'MySQL', 3389:'RDP', 5432:'PostgreSQL', 5900:'VNC', 6379:'Redis',
             8080:'HTTP-Alt', 8443:'HTTPS-Alt', 8888:'HTTP-Alt', 9090:'HTTP-Alt',
             9200:'Elasticsearch', 11211:'Memcached', 27017:'MongoDB'}
    if port in known: return known[port]
    if banner:
        bl = banner.lower()
        if 'ssh' in bl: return 'SSH'
        if 'http' in bl: return 'HTTP'
        if 'ftp' in bl: return 'FTP'
        if 'smtp' in bl: return 'SMTP'
    return '?'


# ─── LAN Scan ───
LAN_STATE = {"scanning": False, "progress": 0, "hosts": [], "findings": [], "subnet": "", "error": None, "network_info": {}, "summary": {}, "started_at": 0}

@app.route('/api/lan-state')
def api_lan_state():
    # Auto-reset stuck scans after 5 minutes
    import time
    if LAN_STATE['scanning'] and LAN_STATE.get('started_at', 0) > 0:
        if time.time() - LAN_STATE['started_at'] > 300:
            LAN_STATE['scanning'] = False
            LAN_STATE['error'] = 'Scan timed out (5 min limit)'
            STATE.log("✗ LAN scan auto-reset: timed out after 5 minutes")
    return jsonify(LAN_STATE)

@app.route('/api/lan-scan', methods=['POST'])
def api_lan_scan():
    import time
    if LAN_STATE['scanning']:
        # Allow force-reset if stuck for >60 seconds
        if time.time() - LAN_STATE.get('started_at', 0) > 60:
            LAN_STATE['scanning'] = False
            STATE.log("⚠ LAN scan: force-reset stale scan")
        else:
            return jsonify({"error": "LAN scan already running"}), 409
    subnet = request.json.get('subnet', '').strip()
    portscan = request.json.get('portscan', 'quick')
    LAN_STATE['started_at'] = time.time()
    t = threading.Thread(target=_run_lan_scan, args=(subnet, portscan), daemon=True)
    t.start()
    return jsonify({"status": "started"})

@app.route('/api/lan-reset', methods=['POST'])
def api_lan_reset():
    """Force reset a stuck LAN scan."""
    global LAN_STATE
    LAN_STATE = {"scanning": False, "progress": 0, "hosts": [], "findings": [], "subnet": "", "error": None, "network_info": {}, "summary": {}, "started_at": 0}
    STATE.log("⚠ LAN scan: manually reset")
    return jsonify({"status": "reset"})

def _run_lan_scan(subnet, portscan_mode):
    global LAN_STATE
    import concurrent.futures, socket, ssl as _ssl
    LAN_STATE = {"scanning": True, "progress": 0, "hosts": [], "findings": [], "subnet": "",
                 "error": None, "network_info": {}, "summary": {}}
    findings = LAN_STATE['findings']

    def add_finding(sev, title, detail, host=''):
        findings.append({"sev": sev, "host": host, "title": title, "detail": detail})

    try:
        STATE.log("▶ LAN scan: discovering local network...")
        LAN_STATE['progress'] = 2

        # ── 1. Network info ──
        subnets, local_ips, gateway, dns_servers = [], [], '', []
        if IS_WIN:
            out = subprocess.check_output("ipconfig /all", text=True, timeout=10,
                                          creationflags=subprocess.CREATE_NO_WINDOW)
            for line in out.split('\n'):
                m = re.search(r'IPv4.*?:\s*(\d+\.\d+\.\d+\.\d+)', line)
                if m and not m.group(1).startswith('127.'):
                    local_ips.append(m.group(1))
                    p = m.group(1).split('.')
                    subnets.append(f"{p[0]}.{p[1]}.{p[2]}.0/24")
                gw = re.search(r'Default Gateway.*?:\s*(\d+\.\d+\.\d+\.\d+)', line)
                if gw: gateway = gw.group(1)
                dns_m = re.search(r'DNS Servers.*?:\s*(\d+\.\d+\.\d+\.\d+)', line)
                if dns_m and dns_m.group(1) not in dns_servers: dns_servers.append(dns_m.group(1))
        else:
            try:
                out = subprocess.check_output("ip -4 addr show | grep inet | grep -v '127.0.0.1'",
                                              shell=True, text=True, timeout=10)
                for line in out.strip().split('\n'):
                    m = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', line)
                    if m:
                        local_ips.append(m.group(1))
                        p = m.group(1).split('.')
                        subnets.append(f"{p[0]}.{p[1]}.{p[2]}.0/24")
            except: pass
            try:
                gw_out = subprocess.check_output("ip route | grep default", shell=True, text=True, timeout=5)
                gw_m = re.search(r'via\s+(\d+\.\d+\.\d+\.\d+)', gw_out)
                if gw_m: gateway = gw_m.group(1)
            except: pass
            try:
                dns_out = subprocess.check_output("cat /etc/resolv.conf | grep nameserver", shell=True, text=True, timeout=5)
                dns_servers = re.findall(r'(\d+\.\d+\.\d+\.\d+)', dns_out)
            except: pass

        if subnet: subnets = [subnet]
        if not subnets:
            LAN_STATE['error'] = "Could not detect network subnets"
            STATE.log("✗ LAN scan: no subnets detected"); return

        LAN_STATE['subnet'] = ', '.join(subnets)
        LAN_STATE['network_info'] = {"local_ips": local_ips, "gateway": gateway, "dns": dns_servers}
        STATE.log(f"▶ LAN scan: subnet(s) {LAN_STATE['subnet']}, gateway {gateway}, local {', '.join(local_ips)}")
        LAN_STATE['progress'] = 5

        # ── 2. Network-level checks ──
        if gateway and gateway in dns_servers:
            add_finding("INFO", f"Router is DNS server ({gateway})",
                        "Your router handles DNS queries. Consider encrypted DNS (1.1.1.1 DoH or 8.8.8.8) for privacy.")
        if dns_servers and not [d for d in dns_servers if d not in local_ips and d != gateway]:
            add_finding("LOW", "No external DNS backup",
                        "Only local/router DNS. Add backup (1.1.1.1 / 8.8.8.8) in case router DNS fails.")
        LAN_STATE['progress'] = 8

        # ── 3. Host discovery ──
        discovered = set()
        mac_map = {}
        try:
            if IS_WIN:
                arp_out = subprocess.check_output("arp -a", text=True, timeout=10,
                                                  creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                arp_out = subprocess.check_output(["arp", "-an"], text=True, timeout=10)
            for line in arp_out.split('\n'):
                ip_m = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                mac_m = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', line)
                if ip_m:
                    ip = ip_m.group(1)
                    if not ip.startswith('255.') and not ip.endswith('.255') and ip != '0.0.0.0':
                        discovered.add(ip)
                        if mac_m: mac_map[ip] = mac_m.group(0)
        except: pass

        base = '.'.join(subnets[0].split('.')[:3])
        STATE.log(f"▶ LAN scan: ping sweep {base}.0/24...")
        LAN_STATE['progress'] = 10

        def ping_host(ip):
            try:
                if IS_WIN:
                    r = subprocess.run(["ping", "-n", "1", "-w", "500", ip],
                                       capture_output=True, timeout=3, creationflags=subprocess.CREATE_NO_WINDOW)
                else:
                    r = subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True, timeout=3)
                return ip if r.returncode == 0 else None
            except: return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(ping_host, f"{base}.{i}"): i for i in range(1, 255)}
            done = 0
            for f in concurrent.futures.as_completed(futures):
                done += 1
                if done % 25 == 0: LAN_STATE['progress'] = 10 + int(20 * done / 254)
                r = f.result()
                if r: discovered.add(r)

        # Refresh ARP after ping
        try:
            if IS_WIN:
                arp2 = subprocess.check_output("arp -a", text=True, timeout=10,
                                               creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                arp2 = subprocess.check_output(["arp", "-an"], text=True, timeout=10)
            for line in arp2.split('\n'):
                ip_m = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                mac_m = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', line)
                if ip_m and mac_m and ip_m.group(1) not in mac_map:
                    mac_map[ip_m.group(1)] = mac_m.group(0)
        except: pass

        discovered = sorted(discovered, key=lambda x: [int(p) for p in x.split('.')])
        if not discovered:
            LAN_STATE['error'] = "No hosts found"; STATE.log("✗ LAN scan: no hosts"); return

        STATE.log(f"▶ LAN scan: {len(discovered)} hosts, scanning ports+services...")
        LAN_STATE['progress'] = 35

        # ── 4. Port scan + deep probes ──
        port_sets = {
            'quick': [21,22,23,25,53,80,110,135,139,443,445,993,995,1433,1883,2049,3306,3389,
                      5000,5432,5900,6379,8080,8443,8883,9090,9200,11211,27017],
            'common': [20,21,22,23,25,53,67,68,80,110,111,135,137,138,139,143,161,389,443,445,
                       465,514,587,631,636,993,995,1080,1433,1521,1883,2049,3000,3306,3389,
                       5000,5060,5432,5900,5901,6379,6443,8000,8080,8443,8888,8883,9090,9200,11211,27017],
            'full': list(range(1, 1025))
        }
        ports = port_sets.get(portscan_mode, port_sets['quick'])

        PORT_SVC = {
            20:'FTP-Data',21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',67:'DHCP',
            80:'HTTP',110:'POP3',111:'RPC',135:'MSRPC',139:'NetBIOS',143:'IMAP',161:'SNMP',
            389:'LDAP',443:'HTTPS',445:'SMB',465:'SMTPS',514:'Syslog',587:'SMTP-Sub',
            631:'IPP',636:'LDAPS',993:'IMAPS',995:'POP3S',1080:'SOCKS',1433:'MSSQL',
            1521:'Oracle',1883:'MQTT',2049:'NFS',3000:'Dev-HTTP',3306:'MySQL',
            3389:'RDP',5000:'AppSvc',5060:'SIP',5432:'PostgreSQL',5900:'VNC',5901:'VNC',
            6379:'Redis',6443:'K8s-API',8000:'HTTP-Dev',8080:'HTTP-Alt',8443:'HTTPS-Alt',
            8883:'MQTT-TLS',8888:'HTTP-Alt',9090:'Prometheus',9200:'Elasticsearch',
            11211:'Memcached',27017:'MongoDB'
        }

        def scan_port(ip, port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5); r = s.connect_ex((ip, port)); s.close()
                return port if r == 0 else None
            except: return None

        def grab_banner(ip, port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2); s.connect((ip, port))
                if port in (80,8080,8000,8888,3000,5000,9090):
                    s.send(b"GET / HTTP/1.0\r\nHost: "+ip.encode()+b"\r\n\r\n")
                elif port in (443,8443):
                    ctx = _ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=_ssl.CERT_NONE
                    ss = ctx.wrap_socket(s, server_hostname=ip)
                    ss.send(b"GET / HTTP/1.0\r\nHost: "+ip.encode()+b"\r\n\r\n")
                    d = ss.recv(512).decode('utf-8',errors='replace'); ss.close(); return d[:200]
                else:
                    s.send(b"\r\n")
                d = s.recv(512).decode('utf-8',errors='replace'); s.close(); return d[:200]
            except: return ''

        def check_ssl(ip, port):
            try:
                ctx = _ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=_ssl.CERT_NONE
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(3)
                ss = ctx.wrap_socket(s, server_hostname=ip); ss.connect((ip, port))
                ver = ss.version(); cipher = ss.cipher(); ss.close()
                return {"version": ver, "cipher": cipher[0] if cipher else ''}
            except: return None

        def check_http_hdrs(ip, port):
            try:
                import urllib.request
                proto = 'https' if port in (443,8443) else 'http'
                ctx = _ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=_ssl.CERT_NONE
                req = urllib.request.Request(f"{proto}://{ip}:{port}/", headers={'User-Agent':'AEGIS/1.0'})
                resp = urllib.request.urlopen(req, timeout=3, context=ctx)
                hdrs = dict(resp.headers); resp.close(); return hdrs
            except: return None

        hosts = []
        total = len(discovered)
        for idx, ip in enumerate(discovered):
            LAN_STATE['progress'] = 35 + int(55 * idx / max(total, 1))
            is_self = ip in local_ips
            is_gw = ip == gateway

            hostname = ''
            try: hostname = socket.gethostbyaddr(ip)[0]
            except: pass

            mac = mac_map.get(ip, '')

            # Parallel port scan
            open_ports = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
                futs = {executor.submit(scan_port, ip, p): p for p in ports}
                for f in concurrent.futures.as_completed(futs):
                    r = f.result()
                    if r: open_ports.append(r)
            open_ports.sort()

            # Banner grab + service ID
            services = []
            for p in open_ports:
                svc = {"port": p, "service": PORT_SVC.get(p, f"port-{p}")}
                if p in (21,22,23,25,80,110,143,443,1883,3306,5432,6379,8080,8443,9200):
                    banner = grab_banner(ip, p)
                    if banner:
                        svc['banner'] = banner[:100]
                        if 'SSH' in banner: svc['version'] = banner.split('\n')[0].strip()
                        elif 'HTTP' in banner:
                            sm = re.search(r'Server:\s*(.+)', banner, re.IGNORECASE)
                            if sm: svc['version'] = sm.group(1).strip()[:60]
                services.append(svc)

            # SSL check
            ssl_info = None
            for p in open_ports:
                if p in (443,8443): ssl_info = check_ssl(ip, p); break

            # HTTP headers check
            http_hdrs = None
            for p in open_ports:
                if p in (80,443,8080,8443,3000,5000,8000,9090):
                    http_hdrs = check_http_hdrs(ip, p); break

            host_info = {
                "ip": ip, "hostname": hostname, "mac": mac,
                "is_self": is_self, "is_gateway": is_gw,
                "open_ports": open_ports, "services": services,
                "port_count": len(open_ports), "ssl": ssl_info,
                "http_headers": http_hdrs is not None
            }
            hosts.append(host_info)

            # ── Findings ──
            label = f"{ip} ({hostname})" if hostname else ip
            op = set(open_ports)

            # Plaintext protocols
            if 23 in op: add_finding("HIGH", f"Telnet on {label}", "Sends credentials in plaintext. Replace with SSH.", ip)
            if 21 in op: add_finding("MEDIUM", f"FTP on {label}", "Sends credentials in cleartext. Use SFTP/SCP.", ip)

            # Remote access
            if 5900 in op or 5901 in op:
                add_finding("MEDIUM", f"VNC on {label}", "VNC often has weak/no encryption. Tunnel through SSH/VPN.", ip)
            if 3389 in op and not is_self:
                add_finding("MEDIUM", f"RDP on {label}", "Ensure NLA enabled + strong passwords. Consider VPN-only.", ip)

            # Databases without default auth
            if 6379 in op: add_finding("HIGH", f"Redis on {label}", "No default auth. Bind to 127.0.0.1 or set requirepass.", ip)
            if 11211 in op: add_finding("HIGH", f"Memcached on {label}", "No auth, DDoS amplification risk. Bind to localhost.", ip)
            if 9200 in op: add_finding("HIGH", f"Elasticsearch on {label}", "No auth in older versions. Enable security.", ip)
            if 27017 in op: add_finding("MEDIUM", f"MongoDB on {label}", "Enable --auth. Default allows unauthenticated access.", ip)
            if 1883 in op: add_finding("MEDIUM", f"MQTT unencrypted on {label}", "IoT data leakage risk. Use TLS (port 8883).", ip)

            # File sharing
            if 445 in op or 139 in op:
                add_finding("MEDIUM", f"SMB on {label}", "Audit shared folders. Disable SMBv1.", ip)
            if 2049 in op: add_finding("MEDIUM", f"NFS on {label}", "Check /etc/exports for overly permissive access.", ip)

            # Directory services
            if 389 in op and 636 not in op:
                add_finding("MEDIUM", f"Unencrypted LDAP on {label}", "Use LDAPS (636) or STARTTLS.", ip)

            # Container/orchestration
            if 6443 in op: add_finding("HIGH", f"K8s API on {label}", "Ensure RBAC + disable anonymous auth.", ip)

            # SSH version
            for svc in services:
                if svc['port'] == 22 and svc.get('version'):
                    v = svc['version']
                    if 'dropbear' in v.lower():
                        add_finding("LOW", f"Dropbear SSH on {label}", f"{v} — often IoT. Check firmware updates.", ip)
                    vm = re.search(r'OpenSSH_(\d+)', v)
                    if vm and int(vm.group(1)) < 8:
                        add_finding("MEDIUM", f"Outdated SSH on {label}", f"{v}. Update to OpenSSH 8+.", ip)

            # HTTP security
            if http_hdrs:
                sec = ['X-Frame-Options','X-Content-Type-Options','Strict-Transport-Security','Content-Security-Policy']
                miss = [h for h in sec if h.lower() not in {k.lower():v for k,v in http_hdrs.items()}]
                if miss and not is_self:
                    add_finding("LOW", f"Missing HTTP headers on {label}", f"Missing: {', '.join(miss)}", ip)
                srv = http_hdrs.get('Server','') or http_hdrs.get('server','')
                if srv and re.search(r'\d+\.\d+', srv):
                    add_finding("LOW", f"Version disclosed on {label}", f"Server: {srv}", ip)

            # TLS version
            if ssl_info and ssl_info.get('version') in ('TLSv1','TLSv1.1','SSLv3'):
                add_finding("HIGH", f"Weak TLS on {label}", f"{ssl_info['version']} is deprecated. Use TLS 1.2+.", ip)

            # Gateway specifics
            if is_gw:
                if 23 in op: add_finding("HIGH", f"Router Telnet ({label})", "Disable Telnet. Use HTTPS admin.", ip)
                if 80 in op and 443 not in op:
                    add_finding("MEDIUM", f"Router HTTP-only ({label})", "Enable HTTPS for admin panel.", ip)
                if 161 in op: add_finding("MEDIUM", f"SNMP on router ({label})", "Use SNMPv3 or disable.", ip)

            # Large attack surface
            if not is_self and not is_gw and len(open_ports) > 10:
                add_finding("MEDIUM", f"Many ports on {label}", f"{len(open_ports)} open — review necessity.", ip)

        LAN_STATE['hosts'] = hosts
        LAN_STATE['progress'] = 95

        # ── 5. Summary ──
        LAN_STATE['summary'] = {
            "total_hosts": len(hosts),
            "total_open_ports": sum(h['port_count'] for h in hosts),
            "hosts_with_http": sum(1 for h in hosts if any(p in h['open_ports'] for p in [80,443,8080,8443])),
            "hosts_with_ssh": sum(1 for h in hosts if 22 in h['open_ports']),
            "hosts_with_smb": sum(1 for h in hosts if 445 in h['open_ports'] or 139 in h['open_ports']),
            "hosts_with_db": sum(1 for h in hosts if any(p in h['open_ports'] for p in [3306,5432,6379,27017,9200,1433,11211])),
            "findings_high": sum(1 for f in findings if f['sev']=='HIGH'),
            "findings_medium": sum(1 for f in findings if f['sev']=='MEDIUM'),
            "findings_low": sum(1 for f in findings if f['sev'] in ('LOW','INFO')),
        }
        LAN_STATE['progress'] = 100
        STATE.log(f"✓ LAN scan: {len(hosts)} hosts, {sum(h['port_count'] for h in hosts)} ports, "
                  f"{len(findings)} findings ({LAN_STATE['summary']['findings_high']} high)")
    except Exception as e:
        LAN_STATE['error'] = str(e)
        STATE.log(f"✗ LAN scan error: {e}")
        import traceback; traceback.print_exc()
    finally:
        LAN_STATE['scanning'] = False

@app.route('/api/external-state')
def api_ext_state():
    return jsonify(EXT_STATE)

@app.route('/api/external-scan', methods=['POST'])
def api_ext_scan():
    host = request.json.get('host', '').strip()
    if not host:
        # Use the connected host
        host = STATE.data.get('hostname', '') or (SSH_CONN.host if SSH_CONN else '')
    if not host:
        return jsonify({"error": "No host specified"}), 400
    if EXT_STATE['scanning']:
        return jsonify({"error": "External scan already running"}), 409
    t = threading.Thread(target=run_external_scan, args=(host,), daemon=True)
    t.start()
    return jsonify({"status": "started", "host": host})

@app.route('/api/ext-fix', methods=['POST'])
def api_ext_fix():
    """Fix an external finding via the internal SSH connection."""
    idx = request.json.get('index')
    findings = EXT_STATE.get('results', {}).get('findings', [])
    if idx is None or idx >= len(findings) or not SSH_CONN:
        return jsonify({"success": False})
    f = findings[idx]
    if not f.get('fix_cmd') or f.get('fixed'):
        return jsonify({"success": False})
    out, code = SSH_CONN.sudo(f['fix_cmd'])
    success = code == 0
    if success:
        f['fixed'] = True
        STATE.add_action(f"[EXT] Fixed: {f['title']}", f['fix_cmd'], f.get('undo_cmd'))
    return jsonify({"success": success, "output": out[:200]})


# ═══════════════════════════════════════════════════
#  HTML DASHBOARD (embedded)
# ═══════════════════════════════════════════════════
HTML_PAGE = r'''<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>AEGIS — Server Security Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#060a12;--bg2:#0c1220;--bg3:#121a2c;--bg4:#1a2540;--border:#1e2d48;--text:#c8d6e5;--dim:#5a7090;--cyan:#00aaff;--green:#00e676;--yellow:#ffd600;--orange:#ff8800;--red:#ff2244;--purple:#b388ff}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.5}
a{color:var(--cyan)}
.login-page{display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
.login-box{background:var(--bg2);border:1px solid var(--border);border-radius:16px;padding:40px;width:100%;max-width:480px}
.login-box h1{color:var(--cyan);font-size:24px;margin-bottom:4px}
.login-box .sub{color:var(--dim);font-size:13px;margin-bottom:24px}
.form-group{margin-bottom:16px}
.form-group label{display:block;color:var(--dim);font-size:12px;margin-bottom:4px;text-transform:uppercase;letter-spacing:0.5px}
.form-group input,.form-group select{width:100%;padding:10px 12px;background:var(--bg3);color:var(--text);border:1px solid var(--border);border-radius:8px;font-size:14px;font-family:inherit;outline:none}
.form-group input:focus{border-color:var(--cyan)}
.form-group .hint{color:var(--dim);font-size:11px;margin-top:3px}
.radio-group{display:flex;gap:16px;margin:8px 0}
.radio-group label{display:flex;align-items:center;gap:6px;cursor:pointer;color:var(--text);font-size:14px;text-transform:none;letter-spacing:0}
.radio-group input[type=radio]{accent-color:var(--cyan)}
.checkbox-row{display:flex;align-items:center;gap:8px;margin:12px 0}
.checkbox-row input{accent-color:var(--cyan)}
.checkbox-row label{color:var(--dim);font-size:13px;cursor:pointer}
.btn-connect{width:100%;padding:12px;background:var(--cyan);color:#000;border:none;border-radius:8px;font-size:15px;font-weight:700;cursor:pointer;margin-top:8px;transition:background .2s}
.btn-connect:hover{background:#0088cc}
.btn-connect:disabled{opacity:0.5;cursor:not-allowed}
.login-error{color:var(--red);font-size:13px;margin-top:8px;display:none}
.login-status{color:var(--cyan);font-size:13px;margin-top:8px;display:none}

/* Dashboard */
.dashboard{display:none;flex-direction:column;padding:16px 24px;max-width:1600px;margin:0 auto}
.header{display:flex;align-items:center;justify-content:space-between;padding:8px 0 16px;border-bottom:1px solid var(--border);margin-bottom:16px;flex-wrap:wrap;gap:8px}
.header h1{font-size:18px;color:var(--cyan)}
.header .host{color:var(--dim);font-size:13px}
#hdr-status{font-size:13px}
.status-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.status-dot.ok{background:var(--green)}.status-dot.warn{background:var(--yellow)}.status-dot.crit{background:var(--red)}

/* Top progress */
#top-progress{position:fixed;top:0;left:0;width:100%;height:3px;z-index:300;display:none}
#top-progress-fill{height:100%;background:linear-gradient(90deg,var(--cyan),var(--green));width:0%;transition:width .3s}

/* Score ring */
.score-ring{position:relative;width:120px;height:120px;flex-shrink:0}
.score-ring svg{width:100%;height:100%;transform:rotate(-90deg)}
.score-ring .score-num{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);font-size:32px;font-weight:800}
#score-summary{text-align:center;margin-top:4px}

/* Cards */
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;margin:12px 0}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px}
.card-label{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--dim)}
.card-val{font-size:22px;font-weight:800;margin:2px 0}
.card-sub{font-size:12px;color:var(--dim)}

/* Sections */
.sections{display:grid;grid-template-columns:repeat(auto-fit,minmax(450px,1fr));gap:14px;margin-top:14px}
.section{background:var(--bg2);border:1px solid var(--border);border-radius:10px;overflow:hidden}
.section-head{display:flex;align-items:center;justify-content:space-between;padding:12px 16px;border-bottom:1px solid var(--border)}
.section-head h3{font-size:14px;font-weight:600}
.section-body{padding:14px 16px;font-size:13px;max-height:400px;overflow-y:auto}

/* Tables */
table{width:100%;border-collapse:collapse}
th{text-align:left;font-size:11px;text-transform:uppercase;color:var(--dim);padding:6px 8px;border-bottom:1px solid var(--border)}
td{padding:6px 8px;border-bottom:1px solid rgba(30,45,72,0.5);font-size:13px}

/* Badges */
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700}
.badge-crit{background:rgba(255,34,68,.15);color:var(--red)}
.badge-high{background:rgba(255,136,0,.15);color:var(--orange)}
.badge-med{background:rgba(255,214,0,.15);color:var(--yellow)}
.badge-low{background:rgba(179,136,255,.15);color:var(--purple)}
.badge-ok{background:rgba(0,230,118,.15);color:var(--green)}
.badge-info{background:rgba(0,170,255,.15);color:var(--cyan)}
.badge-exposed{background:rgba(255,34,68,.2);color:var(--red);animation:pulse 2s infinite}
.badge-filtered{color:var(--cyan)}.badge-local{color:var(--dim)}.badge-expected{color:var(--green)}

/* Buttons */
.btn{padding:5px 12px;border:none;border-radius:6px;cursor:pointer;font-size:12px;font-weight:600}
.btn-cyan{background:var(--cyan);color:#000}.btn-red{background:var(--red);color:#fff}
.btn-ghost{background:var(--bg3);color:var(--text);border:1px solid var(--border)}
.btn-sm{padding:3px 8px;font-size:11px}

/* Findings */
.finding{background:var(--bg3);border-radius:8px;padding:10px 14px;margin-bottom:8px}
.finding-title{font-weight:600;margin-bottom:3px}
.finding-detail{color:var(--dim);font-size:12px;line-height:1.5;margin-top:4px}
.finding-fix{font-family:monospace;font-size:11px;color:var(--dim);margin-top:4px;background:var(--bg);padding:4px 8px;border-radius:4px}
.mgmt-row{display:flex;align-items:center;gap:8px;padding:8px 12px;border-bottom:1px solid var(--border)}
.mgmt-row:last-child{border-bottom:none}
.mgmt-form{display:flex;flex-wrap:wrap;align-items:end;gap:8px;padding:12px;background:var(--bg3);border-radius:8px;margin:10px 0}
.mgmt-form label{display:flex;flex-direction:column;gap:3px;font-size:12px;color:var(--dim)}
.mgmt-form input,.mgmt-form select{background:var(--bg);border:1px solid var(--border);color:var(--text);padding:6px 10px;border-radius:6px;font-size:13px;min-width:80px}
.mgmt-form input:focus,.mgmt-form select:focus{border-color:var(--cyan);outline:none}
.mgmt-controls{display:flex;gap:6px;padding:10px 0;flex-wrap:wrap;align-items:center}
.mgmt-tag{display:inline-flex;align-items:center;gap:4px;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:500}
.mgmt-tag.on{background:rgba(100,255,218,0.15);color:var(--green)}
.mgmt-tag.off{background:rgba(255,85,85,0.15);color:var(--red)}
.mgmt-tag.info{background:rgba(100,200,255,0.1);color:var(--cyan)}
.mgmt-rule{display:flex;align-items:center;gap:8px;padding:6px 12px;font-family:monospace;font-size:12px;border-bottom:1px solid var(--bg3)}
.mgmt-rule:hover{background:var(--bg3)}
.mgmt-rule .rule-num{color:var(--dim);min-width:30px}
.mgmt-rule .rule-text{flex:1;color:var(--text)}
.mgmt-rule .rule-allow{color:var(--green)}
.mgmt-rule .rule-deny{color:var(--red)}
.mgmt-rule .rule-limit{color:var(--orange)}
.site-card{background:var(--bg3);border-radius:8px;padding:12px;margin:6px 0}
.site-card-head{display:flex;align-items:center;gap:8px;margin-bottom:6px}
.site-card-head .site-name{font-weight:600;color:var(--cyan);font-size:14px}
.site-locations{font-size:12px;color:var(--dim);margin-top:6px}
.site-location{padding:3px 0;font-family:monospace}
.btn-red{background:rgba(255,85,85,0.2);color:var(--red);border:1px solid rgba(255,85,85,0.3)}
.btn-red:hover{background:rgba(255,85,85,0.3)}
.btn-green{background:rgba(100,255,218,0.15);color:var(--green);border:1px solid rgba(100,255,218,0.2)}
.btn-green:hover{background:rgba(100,255,218,0.25)}
.config-editor{width:100%;min-height:200px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:6px;font-family:monospace;font-size:12px;padding:10px;resize:vertical;line-height:1.6}
.config-editor:focus{border-color:var(--cyan);outline:none}

/* Attackers bar */
.atk-bar{height:18px;border-radius:3px;background:var(--red);opacity:0.7;min-width:4px;transition:width .3s}

/* Loading */
.loading{color:var(--dim);font-style:italic}

@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.5}}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.section{animation:fadeIn .3s ease}

/* Custom role chips */
.role-chip{display:inline-flex;align-items:center;gap:5px;padding:6px 12px;border-radius:8px;font-size:12px;font-weight:600;cursor:pointer;user-select:none;transition:all .15s;border:1.5px solid var(--border);background:var(--bg3);color:var(--dim)}
.role-chip:hover{border-color:var(--cyan);color:var(--text)}
.role-chip.active{border-color:var(--cyan);background:rgba(0,170,255,.12);color:var(--cyan)}
.role-chip .chip-port{font-weight:400;font-size:10px;opacity:.7}
.role-chip .chip-dot{width:6px;height:6px;border-radius:50%;background:var(--border);transition:background .15s}
.role-chip.active .chip-dot{background:var(--cyan)}

/* Tabs */
.tabs{display:flex;gap:4px;margin:14px 0 0;border-bottom:2px solid var(--border);padding-bottom:0}
.tab{padding:10px 20px;background:none;border:none;color:var(--dim);font-size:13px;font-weight:600;cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-2px;transition:all .2s;font-family:inherit}
.tab:hover{color:var(--text);background:var(--bg2)}
.tab.active{color:var(--cyan);border-bottom-color:var(--cyan)}
.tab-badge{background:var(--red);color:#fff;font-size:10px;padding:1px 6px;border-radius:8px;margin-left:4px}
.tab-badge:empty{display:none}
.tab-content{display:none;margin-top:14px}
.tab-content.active{display:block}
</style>
</head>
<body>

<!-- LOGIN PAGE -->
<div class="login-page" id="login-page">
  <div class="login-box">
    <h1>◆ AEGIS</h1>
    <div class="sub">Server Security Dashboard v5.7</div>

    <div class="form-group">
      <label>Server IP / Hostname</label>
      <input type="text" id="login-host" placeholder="Server IP or hostname">
    </div>
    <div class="form-group">
      <label>SSH Username</label>
      <input type="text" id="login-user" placeholder="Username">
    </div>
    <div class="form-group">
      <label>Authentication</label>
      <div class="radio-group">
        <label><input type="radio" name="auth" value="key" checked onchange="toggleAuth()"> SSH Key</label>
        <label><input type="radio" name="auth" value="password" onchange="toggleAuth()"> Password</label>
      </div>
    </div>
    <div class="form-group" id="key-group">
      <label>SSH Key Path</label>
      <input type="text" id="login-key" placeholder="Leave blank to auto-detect">
      <div class="hint">Auto-detects id_ed25519, id_rsa, id_ecdsa</div>
    </div>
    <div class="form-group" id="sshpass-group" style="display:none">
      <label>SSH Password</label>
      <input type="password" id="login-sshpass">
    </div>
    <div class="form-group">
      <label>Sudo Password</label>
      <input type="password" id="login-sudo">
      <div class="hint">Required for firewall, ports, and system scans. <span id="sudo-saved-hint" style="color:var(--green);display:none">🔒 Saved (encrypted)</span></div>
    </div>
    <div class="form-group">
      <label>Server Role</label>
      <select id="login-role" onchange="toggleCustomRole()">
        <option value="general">General Purpose (only SSH expected)</option>
        <option value="web">Web Server (SSH + HTTP/HTTPS)</option>
        <option value="database">Database Server (SSH + DB ports)</option>
        <option value="mail">Mail Server (SMTP/IMAP/POP3)</option>
        <option value="web+db">Web + Database (HTTP + DB)</option>
        <option value="bastion">Bastion Host (SSH only, minimal)</option>
        <option value="custom">✎ Custom — choose expected services</option>
      </select>
      <div class="hint">Adjusts which services and ports are expected vs flagged</div>
    </div>
    <div id="custom-role-panel" style="display:none;margin-bottom:16px">
      <div style="font-size:12px;color:var(--dim);text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px">Expected Services <span style="text-transform:none;letter-spacing:0">(click to toggle)</span></div>
      <div id="custom-chips" style="display:flex;flex-wrap:wrap;gap:6px"></div>
      <div style="margin-top:8px;font-size:11px;color:var(--dim)">
        <span id="custom-summary">0 services, 0 ports selected</span>
      </div>
    </div>
    <div class="checkbox-row">
      <input type="checkbox" id="login-save" checked>
      <label for="login-save">Remember connection settings</label>
    </div>
    <button class="btn-connect" id="btn-connect" onclick="doConnect()">▶ Launch Dashboard</button>
    <div style="margin-top:12px;text-align:center;padding-top:12px;border-top:1px solid var(--border)">
      <button onclick="launchLanOnly()" style="background:none;border:1px solid var(--cyan);color:var(--cyan);padding:8px 20px;border-radius:8px;cursor:pointer;font-size:13px;width:100%">📡 LAN Scan Only — no server connection needed</button>
    </div>
    <div class="login-error" id="login-error"></div>
    <div class="login-status" id="login-status"></div>
    <div style="margin-top:16px;text-align:center">
      <a href="#" onclick="stopServer();return false" style="color:var(--dim);font-size:11px;text-decoration:none;opacity:.6">⏻ Stop AEGIS Server</a>
    </div>
  </div>
</div>

<!-- DASHBOARD -->
<div id="top-progress"><div id="top-progress-fill"></div></div>
<div class="dashboard" id="dashboard">
  <div class="header">
    <div><h1>◆ AEGIS</h1><span class="host" id="hdr-host">Connecting...</span></div>
    <div style="display:flex;align-items:center;gap:16px">
      <span id="hdr-status"><span class="status-dot warn"></span>Scanning...</span>
      <button class="btn btn-cyan" onclick="rescan()">↻ Rescan</button>
      <button class="btn btn-ghost" onclick="extScan()">🌐 External Scan</button>
      <button class="btn btn-ghost" onclick="goSettings()">⚙ Settings</button>
    </div>
  </div>
  <div id="sudo-warning" style="display:none;background:rgba(255,136,0,.1);border:1px solid var(--orange);border-radius:8px;padding:10px 16px;margin-bottom:12px;font-size:13px;color:var(--orange)">
    ⚠ <b>Scan incomplete</b> — <span id="sudo-skip-count"></span> sections require sudo access. Provide sudo password and rescan for full results.
  </div>
  <div id="scan-diff" style="display:none;background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:10px 16px;margin-bottom:12px;font-size:12px"></div>

  <div style="display:flex;gap:24px;align-items:center;flex-wrap:wrap">
    <div class="score-ring">
      <svg viewBox="0 0 100 100"><circle cx="50" cy="50" r="42" fill="none" stroke="var(--bg3)" stroke-width="8"/>
      <circle id="score-arc" cx="50" cy="50" r="42" fill="none" stroke="var(--green)" stroke-width="8"
        stroke-dasharray="264" stroke-dashoffset="264" stroke-linecap="round" style="transition:stroke-dashoffset 1s,stroke .5s"/></svg>
      <div class="score-num" id="score-num">--</div>
    </div>
    <div><div id="score-summary"></div><div id="system-info" style="display:flex;gap:16px;flex-wrap:wrap;font-size:13px;color:var(--dim);margin-top:6px"></div></div>
  </div>

  <div class="cards" id="cards"></div>

  <!-- Tab Navigation -->
  <div class="tabs">
    <button class="tab active" onclick="switchTab('internal',this)">🛡 Internal Scan</button>
    <button class="tab" onclick="switchTab('external',this)">🌐 External Scan</button>
    <button class="tab" onclick="switchTab('lan',this)">📡 LAN Scan</button>
    <button class="tab" onclick="switchTab('manage',this)">🔧 Manage</button>
    <button class="tab" onclick="switchTab('findings',this)">🚨 Findings <span id="tab-findings-count" class="tab-badge"></span></button>
    <button class="tab" onclick="switchTab('log',this)">📋 Log</button>
  </div>

  <!-- Tab: Internal Scan -->
  <div class="tab-content active" id="tab-internal">
    <div class="sections">
      <div class="section"><div class="section-head"><h3>🔌 Ports & Services</h3><span id="ports-count" class="badge badge-info"></span></div><div class="section-body" id="ports-body"><span class="loading">Scanning...</span></div></div>
      <div class="section"><div class="section-head"><h3>🛡 Firewall</h3><span id="fw-status"></span></div><div class="section-body" id="fw-body"><span class="loading">Scanning...</span></div></div>
      <div class="section"><div class="section-head"><h3>🔑 SSH & fail2ban</h3></div><div class="section-body" id="ssh-body"><span class="loading">Scanning...</span></div></div>
      <div class="section"><div class="section-head"><h3>⚔ Brute Force Attackers</h3><span id="attack-count"></span></div><div class="section-body" id="attack-body"><span class="loading">Scanning...</span></div></div>
      <div class="section"><div class="section-head"><h3>🔄 Running Processes</h3><span id="proc-count"></span></div><div class="section-body" id="proc-body"><span class="loading">Scanning...</span></div></div>
      <div class="section"><div class="section-head"><h3>🌐 Network Connections</h3><span id="net-count"></span></div><div class="section-body" id="net-body"><span class="loading">Scanning...</span></div></div>
      <div class="section"><div class="section-head"><h3>⚙ Startup Services</h3><span id="svc-count"></span></div><div class="section-body" id="svc-body"><span class="loading">Scanning...</span></div></div>
      <div class="section"><div class="section-head"><h3>⏰ Scheduled Tasks</h3><span id="cron-count"></span></div><div class="section-body" id="cron-body"><span class="loading">Scanning...</span></div></div>
      <div class="section"><div class="section-head"><h3>🧬 Kernel Security</h3></div><div class="section-body" id="kernel-body"><span class="loading">Scanning...</span></div></div>
      <div class="section"><div class="section-head"><h3>🔐 Login History</h3></div><div class="section-body" id="login-body"><span class="loading">Scanning...</span></div></div>
    </div>
  </div>

  <!-- Tab: External Scan -->
  <div class="tab-content" id="tab-external">
    <div class="sections">
      <div class="section" style="grid-column:1/-1"><div class="section-head"><h3>🌐 External Exposure Scan</h3><span id="ext-status"></span><button class="btn btn-sm btn-cyan" style="margin-left:auto" onclick="extScan()">▶ Run External Scan</button></div><div class="section-body" id="ext-body" style="max-height:none"><div style="color:var(--dim);padding:20px;text-align:center"><div style="font-size:40px;margin-bottom:12px">🌐</div><div style="font-size:15px;margin-bottom:6px">External Exposure Scanner</div><div style="font-size:13px">Probes your server's public IP from the outside — shows what an attacker sees.<br>Checks open ports, HTTP security headers, SSL/TLS, SSH banner, and DNS.</div><button class="btn btn-cyan" style="margin-top:16px" onclick="extScan()">▶ Start External Scan</button></div></div></div>
    </div>
  </div>

  <!-- Tab: LAN Scan -->
  <div class="tab-content" id="tab-lan">
    <div class="sections">
      <div class="section" style="grid-column:1/-1">
        <div class="section-head"><h3>📡 LAN Network Discovery</h3><span id="lan-status"></span>
          <div style="margin-left:auto;display:flex;gap:6px">
            <button class="btn btn-sm btn-cyan" id="btn-lan-scan" onclick="lanScan()">▶ Scan LAN</button>
          </div>
        </div>
        <div class="section-body" id="lan-body" style="max-height:none">
          <div style="padding:16px;color:var(--dim)">
            <p style="margin:0 0 8px">Discovers hosts on your local network, checks open ports, and identifies potential security issues. Runs locally — no server connection needed.</p>
            <div style="display:flex;gap:8px;align-items:center;margin-top:10px">
              <label style="font-size:12px">Subnet:</label>
              <input id="lan-subnet" placeholder="auto-detect" style="background:var(--bg);color:var(--text);border:1px solid var(--border);padding:4px 8px;border-radius:4px;font-size:12px;width:160px">
              <label style="font-size:12px">Port scan:</label>
              <select id="lan-portscan" style="background:var(--bg);color:var(--text);border:1px solid var(--border);padding:4px 8px;border-radius:4px;font-size:12px">
                <option value="quick">Quick (top 20)</option>
                <option value="common">Common (top 100)</option>
                <option value="full">Full (1-1024)</option>
              </select>
            </div>
          </div>
        </div>
      </div>
      <div class="section" style="grid-column:1/-1;display:none" id="lan-results-section">
        <div class="section-head"><h3>🖥 Discovered Hosts</h3><span id="lan-host-count"></span></div>
        <div class="section-body" id="lan-results" style="max-height:none;overflow-y:auto"></div>
      </div>
      <div class="section" style="grid-column:1/-1;display:none" id="lan-findings-section">
        <div class="section-head"><h3>⚠ LAN Security Issues</h3><span id="lan-finding-count"></span></div>
        <div class="section-body" id="lan-findings" style="max-height:none"></div>
      </div>
    </div>
  </div>

  <!-- Tab: Manage -->
  <div class="tab-content" id="tab-manage">
    <div class="sections">
      <div class="section" style="grid-column:1/-1">
        <div class="section-head"><h3>🛡 UFW Firewall Management</h3><span id="ufw-mgmt-status"></span>
          <div style="margin-left:auto;display:flex;gap:6px">
            <button class="btn btn-sm btn-cyan" onclick="ufwRefresh()">⟳ Refresh</button>
          </div>
        </div>
        <div class="section-body" id="ufw-mgmt-body" style="max-height:none">
          <div style="text-align:center;color:var(--dim);padding:20px">Click Refresh to load UFW status</div>
        </div>
      </div>
      <div class="section" style="grid-column:1/-1">
        <div class="section-head"><h3>🚫 Fail2ban Management</h3><span id="f2b-mgmt-status"></span>
          <div style="margin-left:auto;display:flex;gap:6px">
            <button class="btn btn-sm btn-cyan" onclick="f2bRefresh()">⟳ Refresh</button>
          </div>
        </div>
        <div class="section-body" id="f2b-mgmt-body" style="max-height:none">
          <div style="text-align:center;color:var(--dim);padding:20px">Click Refresh to load fail2ban status</div>
        </div>
      </div>
      <div class="section" style="grid-column:1/-1">
        <div class="section-head"><h3>🌐 Nginx Management</h3><span id="nginx-mgmt-status"></span>
          <div style="margin-left:auto;display:flex;gap:6px">
            <button class="btn btn-sm btn-cyan" onclick="nginxRefresh()">⟳ Refresh</button>
          </div>
        </div>
        <div class="section-body" id="nginx-mgmt-body" style="max-height:none">
          <div style="text-align:center;color:var(--dim);padding:20px">Click Refresh to load Nginx status</div>
        </div>
      </div>
    </div>
  </div>

  <!-- Tab: Findings -->
  <div class="tab-content" id="tab-findings">
    <div class="sections">
      <div class="section" style="grid-column:1/-1"><div class="section-head"><h3>🚨 Findings</h3><span id="findings-count"></span><button class="btn btn-sm btn-cyan" style="margin-left:auto" onclick="fixAll()">Fix All</button></div><div class="section-body" id="findings-body" style="max-height:none"><span class="loading">Scanning...</span></div></div>
      <div class="section"><div class="section-head"><h3>📝 Action Log</h3></div><div class="section-body" id="actions-body" style="max-height:none"></div></div>
    </div>
  </div>

  <!-- Tab: Log -->
  <div class="tab-content" id="tab-log">
    <div class="sections">
      <div class="section" style="grid-column:1/-1"><div class="section-head"><h3>🖥 Scan Console</h3><span id="log-count" style="color:var(--dim);font-size:12px"></span></div><div class="section-body" id="log-body" style="max-height:none;overflow-y:auto;font-family:monospace;font-size:12px;line-height:1.8"></div></div>
    </div>
  </div>
</div>

<script>
const $ = s => document.querySelector(s);
const h = s => s ? String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;') : '';
let D = null, polling = false;

function switchTab(name,btn){
  document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  const el=document.getElementById('tab-'+name);
  if(el)el.classList.add('active');
  if(btn)btn.classList.add('active');
  // Auto-start external scan when switching to that tab if not done
  if(name==='external'&&!EXT_STATE_LOADED){extScan();}
  // Auto-load manage panels on first visit
  if(name==='manage'&&!MANAGE_LOADED){MANAGE_LOADED=true;ufwRefresh();f2bRefresh();nginxRefresh();}
}
let EXT_STATE_LOADED=false;
let MANAGE_LOADED=false;

// ─── Login ───
// Available services for custom role picker
const CUSTOM_SERVICES = [
  {id:'ssh',      label:'SSH',          ports:['22'],   services:[], cat:'core'},
  {id:'http',     label:'HTTP',         ports:['80'],   services:['nginx','apache2','httpd'], cat:'web'},
  {id:'https',    label:'HTTPS',        ports:['443'],  services:['nginx','apache2','httpd'], cat:'web'},
  {id:'postgres', label:'PostgreSQL',   ports:['5432'], services:['postgresql'], cat:'database'},
  {id:'mysql',    label:'MySQL/MariaDB',ports:['3306'], services:['mysql','mariadb'], cat:'database'},
  {id:'mongodb',  label:'MongoDB',      ports:['27017'],services:['mongod'], cat:'database'},
  {id:'redis',    label:'Redis',        ports:['6379'], services:['redis-server'], cat:'database'},
  {id:'smtp',     label:'SMTP',         ports:['25','587'],services:['postfix','sendmail','exim4'], cat:'mail'},
  {id:'imap',     label:'IMAP',         ports:['143','993'],services:['dovecot','courier-imap'], cat:'mail'},
  {id:'pop3',     label:'POP3',         ports:['110','995'],services:['dovecot'], cat:'mail'},
  {id:'dns',      label:'DNS',          ports:['53'],   services:['bind9','named'], cat:'network'},
  {id:'ftp',      label:'FTP',          ports:['21'],   services:['vsftpd','proftpd','pure-ftpd'], cat:'file'},
  {id:'rdp',      label:'RDP',          ports:['3389'], services:['xrdp'], cat:'remote'},
  {id:'vnc',      label:'VNC',          ports:['5900'], services:[], cat:'remote'},
  {id:'elastic',  label:'Elasticsearch',ports:['9200'], services:['elasticsearch'], cat:'database'},
  {id:'memcache', label:'Memcached',    ports:['11211'],services:['memcached'], cat:'database'},
  {id:'proxy',    label:'Squid Proxy',  ports:['3128'], services:['squid'], cat:'network'},
  {id:'nfs',      label:'NFS',          ports:['2049'], services:['nfs-server','nfs-kernel-server'], cat:'network'},
];
const CAT_ICONS = {core:'🔑',web:'🌐',database:'🗄',mail:'📧',network:'🔗',file:'📂',remote:'🖥'};
let customSelections = new Set(['ssh']); // SSH always starts selected

function buildCustomChips() {
  const container = $('#custom-chips');
  let html = '';
  let lastCat = '';
  CUSTOM_SERVICES.forEach(svc => {
    if(svc.cat !== lastCat) {
      if(lastCat) html += '<div style="width:100%;height:0"></div>';
      lastCat = svc.cat;
    }
    const active = customSelections.has(svc.id);
    const portLabel = svc.ports.join(', ');
    html += `<div class="role-chip${active?' active':''}" data-svc-id="${svc.id}" onclick="toggleChip('${svc.id}',this)">` +
      `<span class="chip-dot"></span>${CAT_ICONS[svc.cat]||''} ${svc.label} <span class="chip-port">:${portLabel}</span></div>`;
  });
  container.innerHTML = html;
  updateCustomSummary();
}

function toggleChip(id, el) {
  if(customSelections.has(id)) { customSelections.delete(id); el.classList.remove('active'); }
  else { customSelections.add(id); el.classList.add('active'); }
  updateCustomSummary();
}

function updateCustomSummary() {
  const ports = new Set();
  const services = new Set();
  customSelections.forEach(id => {
    const svc = CUSTOM_SERVICES.find(s=>s.id===id);
    if(svc) { svc.ports.forEach(p=>ports.add(p)); svc.services.forEach(s=>services.add(s)); }
  });
  const el = $('#custom-summary');
  if(el) el.textContent = `${customSelections.size} services, ${ports.size} ports selected: ${[...ports].sort((a,b)=>a-b).join(', ')}`;
}

function toggleCustomRole() {
  const role = $('#login-role').value;
  const panel = $('#custom-role-panel');
  if(role === 'custom') {
    panel.style.display = 'block';
    buildCustomChips();
  } else {
    panel.style.display = 'none';
  }
}

function getCustomRoleData() {
  const ports = new Set();
  const services = new Set();
  customSelections.forEach(id => {
    const svc = CUSTOM_SERVICES.find(s=>s.id===id);
    if(svc) { svc.ports.forEach(p=>ports.add(p)); svc.services.forEach(s=>services.add(s)); }
  });
  return { expected_ports: [...ports], expected_services: [...services], custom_ids: [...customSelections] };
}

function toggleAuth() {
  const mode = document.querySelector('input[name=auth]:checked').value;
  $('#key-group').style.display = mode==='key'?'block':'none';
  $('#sshpass-group').style.display = mode==='password'?'block':'none';
}

// Load saved config
fetch('/api/config').then(r=>r.json()).then(cfg => {
  if (cfg.host) $('#login-host').value = cfg.host;
  if (cfg.user) $('#login-user').value = cfg.user;
  if (cfg.key_file) $('#login-key').value = cfg.key_file;
  if (cfg.sudo_pass) { $('#login-sudo').value = cfg.sudo_pass; const sh=$('#sudo-saved-hint'); if(sh) sh.style.display='inline'; }
  if (cfg.auth_mode === 'password') {
    document.querySelector('input[name=auth][value=password]').checked = true;
    toggleAuth();
    if (cfg.ssh_pass) $('#login-sshpass').value = cfg.ssh_pass;
  }
  if (cfg.server_role) {
    $('#login-role').value = cfg.server_role;
    if (cfg.server_role === 'custom' && cfg.custom_ids) {
      customSelections = new Set(cfg.custom_ids);
      toggleCustomRole();
    }
  }
});

let _connectInFlight = false;
function launchLanOnly(){
  $('#login-page').style.display='none';
  $('#dashboard').style.display='flex';
  $('#hdr-host').textContent='Local Network Scan';
  $('#hdr-status').innerHTML='<span class="status-dot ok"></span>LAN Mode';
  // Show only LAN, External, and Log tabs
  document.querySelectorAll('.tab').forEach(t=>{
    const txt=t.textContent.toLowerCase();
    if(txt.includes('internal')||txt.includes('manage')||txt.includes('findings')){
      t.style.display='none';
    }
  });
  switchTab('lan',document.querySelector('.tab[onclick*="lan"]'));
}
function doConnect() {
  if (_connectInFlight) return;
  _connectInFlight = true;
  const btn = $('#btn-connect');
  const err = $('#login-error');
  const status = $('#login-status');
  btn.disabled = true;
  btn.textContent = 'Connecting...';
  err.style.display = 'none';
  status.style.display = 'block';
  status.textContent = 'Establishing SSH connection...';

  const authMode = document.querySelector('input[name=auth]:checked').value;
  const roleVal = $('#login-role').value;
  const body = {
    host: $('#login-host').value,
    user: $('#login-user').value,
    auth_mode: authMode,
    key_file: authMode==='key' ? $('#login-key').value : '',
    ssh_pass: authMode==='password' ? $('#login-sshpass').value : '',
    sudo_pass: $('#login-sudo').value,
    save_config: $('#login-save').checked,
    server_role: roleVal,
  };
  if (roleVal === 'custom') {
    const cd = getCustomRoleData();
    body.custom_expected_ports = cd.expected_ports;
    body.custom_expected_services = cd.expected_services;
    body.custom_ids = cd.custom_ids;
  }

  fetch('/api/connect', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)})
    .then(r => r.json())
    .then(d => {
      _connectInFlight = false;
      if (d.error) {
        err.textContent = d.error;
        err.style.display = 'block';
        btn.disabled = false;
        btn.textContent = '▶ Launch Dashboard';
        status.style.display = 'none';
      } else {
        SSH_CONN_HOST = body.host;
        // Switch to dashboard immediately
        $('#login-page').style.display = 'none';
        $('#dashboard').style.display = 'flex';
        startPolling();
      }
    })
    .catch(e => {
      _connectInFlight = false;
      err.textContent = 'Network error: ' + e;
      err.style.display = 'block';
      btn.disabled = false;
      btn.textContent = '▶ Launch Dashboard';
    });
}

// Enter key to connect
document.querySelectorAll('#login-page input').forEach(el => {
  el.addEventListener('keydown', e => { if (e.key === 'Enter') doConnect(); });
});

// ─── Polling ───
function startPolling() { if (!polling) { polling = true; poll(); } }

function poll() {
  fetch('/api/state').then(r=>r.json()).then(d => {
    D = d;
    if (d.scanning) {
      $('#top-progress').style.display = 'block';
      $('#top-progress-fill').style.width = d.progress + '%';
      $('#hdr-status').innerHTML = `<span class="status-dot warn"></span>${d.current_module||'Scanning'}... ${d.progress}%`;
    } else {
      $('#top-progress').style.display = 'none';
      if (d.connected) {
        $('#hdr-status').innerHTML = `<span class="status-dot ok"></span>Connected`;
      } else if (d.error) {
        $('#hdr-status').innerHTML = `<span class="status-dot crit"></span>${h(d.error)}`;
      }
    }
    if (d.data && Object.keys(d.data).length > 0) render(d);
    renderLog(d);
    // Sudo warning
    const sw=$('#sudo-warning');
    if(sw&&d.sudo_sections_skipped&&d.sudo_sections_skipped.length>0&&!d.scanning){
      sw.style.display='block';
      $('#sudo-skip-count').textContent=d.sudo_sections_skipped.length;
    } else if(sw) { sw.style.display='none'; }
    // Scan diff
    const sd=$('#scan-diff');
    if(sd&&d.scan_diff&&!d.scanning){
      const df=d.scan_diff;
      let dh=`<span style="color:var(--cyan)">Δ vs last scan:</span> Score ${df.score_change>=0?'+':''}${df.score_change}`;
      if(df.new_findings.length) dh+=` | <span style="color:var(--red)">+${df.new_findings.length} new</span>`;
      if(df.resolved_findings.length) dh+=` | <span style="color:var(--green)">-${df.resolved_findings.length} resolved</span>`;
      sd.innerHTML=dh; sd.style.display='block';
    } else if(sd) { sd.style.display='none'; }
    setTimeout(poll, d.scanning ? 600 : 5000);
  }).catch(() => setTimeout(poll, 3000));
}

// ─── Render ───
function render(d) {
  const data = d.data || {};
  const sys = data.system || {};

  $('#hdr-host').textContent = data.hostname ? `${data.hostname} — ${sys.os||''}` : 'Connecting...';

  // Score
  const score = d.score || 0;
  const color = score >= 80 ? '#00e676' : score >= 60 ? '#ffd600' : '#ff2244';
  const arc = $('#score-arc');
  if (arc) { arc.style.stroke = color; arc.style.strokeDashoffset = 264 - (264 * score / 100); }
  const sn = $('#score-num');
  if (sn) { sn.textContent = score; sn.style.color = color; }

  const findings = d.findings || [];
  const crits = findings.filter(f=>f.sev==='CRITICAL'&&!f.fixed).length;
  const highs = findings.filter(f=>f.sev==='HIGH'&&!f.fixed).length;
  const meds = findings.filter(f=>f.sev==='MEDIUM'&&!f.fixed).length;
  const fixed = findings.filter(f=>f.fixed).length;
  $('#score-summary').innerHTML = `<span class="badge badge-crit">${crits} CRIT</span> <span class="badge badge-high">${highs} HIGH</span> <span class="badge badge-med">${meds} MED</span> <span class="badge badge-ok">${fixed} FIXED</span>${d.scanning?' <span style="color:var(--cyan)">scanning...</span>':''}`;
  $('#system-info').innerHTML = `<span>Kernel: ${h(sys.kernel||'...')}</span><span>Up: ${h(sys.uptime||'...')}</span><span>Mem: ${h(sys.memory||'...')}</span><span>Disk: ${h(sys.disk||'...')}</span>`;

  // Cards
  const fw = data.firewall||{}, ssh = data.ssh||{}, logs = data.logs||{}, updates = data.updates||{}, files = data.files||{}, appd = data.app||{}, procs = data.processes||{}, svcs = data.services||{}, net = data.network||{}, kern = data.kernel||{}, audit = data.audit||{};
  const ports = data.ports||[];
  const exposed = ports.filter(p=>p.exposure==='exposed').length;
  const lo = '<span style="color:var(--dim)">...</span>';

  $('#cards').innerHTML = [
    card('Firewall', fw.active!=null?(fw.active?'Active':'INACTIVE'):lo, fw.active==null?'dim':fw.active?'green':'red', fw.default_in||'...'),
    card('Ports', ports.length?`${ports.length}`:lo, exposed?'red':ports.length?'green':'dim', `${exposed} exposed`),
    card('fail2ban', ssh.f2b_active!=null?(ssh.f2b_active?'Active':'OFF'):lo, ssh.f2b_active==null?'dim':ssh.f2b_active?'green':'red', ssh.f2b_active?`${ssh.f2b_banned_now} banned`:''),
    card('Attacks/24h', logs.failed_24h!=null?`${logs.failed_24h}`:lo, (logs.failed_24h||0)>100?'red':(logs.failed_24h||0)>10?'yellow':'green', `${(logs.attackers||[]).length} IPs`),
    card('Processes', procs.top?`${procs.top.length}`:lo, (procs.suspicious||[]).length?'red':'green', `${(procs.suspicious||[]).length} suspicious`),
    card('Services', svcs.enabled?`${svcs.enabled.length}`:lo, (svcs.risky||[]).length?'orange':'green', `${(svcs.risky||[]).length} risky`),
    card('Network', net.connections?`${net.connections.length}`:lo, 'cyan', `${(net.outbound||[]).length} outbound`),
    card('Kernel', kern.issues?`${kern.issues.length} issues`:lo, (kern.issues||[]).length?'orange':'green', kern.settings?`${kern.settings.length} checked`:''),
    card('Updates', updates.packages?`${updates.packages.length}`:lo, (updates.packages||[]).length?'orange':'green', updates.auto_updates?'Auto on':'Auto off'),
    card('Audit', audit.active!=null?(audit.active?'Active':'OFF'):lo, audit.active==null?'dim':audit.active?'green':'red', audit.rules!=null?`${audit.rules} rules`:''),
  ].join('');

  // Ports
  if (ports.length) {
    let t='<table><tr><th>Port</th><th>Proto</th><th>Process</th><th>Address</th><th>Exposure</th></tr>';
    ports.forEach(p=>{
      const bc={'exposed':'badge-exposed','filtered':'badge-filtered','localhost':'badge-local','expected':'badge-expected'}[p.exposure]||'badge-info';
      const lb={'exposed':'★ EXPOSED','filtered':'Filtered','localhost':'Localhost','expected':'Expected'}[p.exposure]||p.exposure;
      t+=`<tr><td style="font-weight:700;color:var(--cyan)">${h(p.port)}</td><td>${h(p.proto)}</td><td>${h(p.process)}</td><td style="font-family:monospace;font-size:12px">${h(p.addr)}</td><td><span class="badge ${bc}">${lb}</span></td></tr>`;
    });
    t+='</table>';$('#ports-body').innerHTML=t;$('#ports-count').textContent=`${ports.length} ports`;
  }

  // Firewall
  if(fw.active!=null){
    $('#fw-status').innerHTML=fw.active?'<span class="badge badge-ok">Active</span>':'<span class="badge badge-crit">INACTIVE</span>';
    let f=`<div style="margin-bottom:8px"><b>Default:</b> ${fw.default_in} | <b>Allowed:</b> ${(fw.allowed_ports||[]).join(', ')||'none'} | <b>Blocked IPs:</b> ${(fw.blocked_ips||[]).length}</div>`;
    if((fw.rules||[]).length){f+='<table><tr><th>Rule</th></tr>';fw.rules.forEach(r=>{const c=r.includes('DENY')?'var(--red)':r.includes('ALLOW')?'var(--green)':'var(--text)';f+=`<tr><td style="color:${c};font-family:monospace;font-size:12px">${h(r)}</td></tr>`;});f+='</table>';}
    $('#fw-body').innerHTML=f;
  }

  // SSH
  if(ssh.settings){
    let s='<table><tr><th>Setting</th><th>Value</th><th>Status</th></tr>';
    (ssh.settings||[]).forEach(st=>{s+=`<tr><td>${h(st.key)}</td><td style="font-family:monospace">${h(st.value)}</td><td><span class="badge ${st.safe?'badge-ok':'badge-'+({CRITICAL:'crit',HIGH:'high',MEDIUM:'med'}[st.sev]||'med')}">${st.safe?'OK':st.sev}</span></td></tr>`;});
    s+='</table>';
    s+=`<div style="margin-top:10px;color:var(--dim)">Keys: ${ssh.has_keys?ssh.key_count+' found':'<span style="color:var(--red)">NONE</span>'} | fail2ban: ${ssh.f2b_active?'<span style="color:var(--green)">active</span> ('+ssh.f2b_banned_now+' now / '+ssh.f2b_banned_total+' total)':'<span style="color:var(--red)">off</span>'}</div>`;
    if(ssh.f2b_active && ssh.f2b_config){
      const c=ssh.f2b_config;
      const bt=c.bantime||600; const mr=c.maxretry||5; const ft=c.findtime||600;
      const isWeak=bt<3600||mr>3||ft<600;
      s+=`<div style="margin-top:8px;padding:10px 12px;background:var(--bg3);border-radius:8px;font-size:12px">`;
      s+=`<div style="margin-bottom:4px;font-weight:600;color:${isWeak?'var(--orange)':'var(--green)'}">fail2ban Config ${isWeak?'⚠ Lenient':'✓ Hardened'}</div>`;
      s+=`<span style="color:${bt<3600?'var(--orange)':'var(--text)'}">Ban: ${bt>=86400?Math.round(bt/86400)+'d':bt>=3600?Math.round(bt/3600)+'h':Math.round(bt/60)+'min'}</span>`;
      s+=` · <span style="color:${mr>3?'var(--orange)':'var(--text)'}">Max retries: ${mr}</span>`;
      s+=` · <span style="color:${ft<600?'var(--orange)':'var(--text)'}">Window: ${ft>=3600?Math.round(ft/3600)+'h':Math.round(ft/60)+'min'}</span>`;
      if(c.bantime_increment) s+=` · <span style="color:var(--green)">Escalating ✓</span>`;
      if(isWeak) s+=`<div style="margin-top:8px"><button class="btn btn-sm btn-cyan" onclick="hardenF2b(this)">🛡 Harden: 24h ban, 3 retries, escalating</button></div>`;
      s+=`</div>`;
    }
    $('#ssh-body').innerHTML=s;
  }

  // Attackers
  if(data.logs){
    const attackers=logs.attackers||[];
    const maxC=attackers.length?Math.max(...attackers.map(a=>a.count)):1;
    let a='';
    if(attackers.length){
      a+=`<div style="margin-bottom:8px"><button class="btn btn-sm btn-red" onclick="blockAttackers()">Block Top 10 Unblocked</button></div>`;
      attackers.forEach(at=>{const w=Math.max(4,at.count/maxC*100);const st=at.banned?'badge-ok':at.blocked?'badge-info':'badge-crit';const sl=at.banned?'Banned':at.blocked?'Blocked':'Active';a+=`<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px"><span style="min-width:45px;text-align:right;font-weight:700;font-size:12px">${at.count}</span><span style="min-width:120px;font-family:monospace;font-size:12px">${h(at.ip)}</span><div class="atk-bar" style="width:${w}%"></div><span class="badge ${st}">${sl}</span>${!at.banned&&!at.blocked?`<button class="btn btn-sm btn-ghost" onclick="blockIP('${at.ip}',this)">Block</button>`:''}</div>`;});
    }else a='<span class="loading">No attackers detected</span>';
    $('#attack-body').innerHTML=a;$('#attack-count').innerHTML=`<span style="color:${(logs.failed_24h||0)>100?'var(--red)':'var(--dim)'}">${logs.failed_24h||0}/24h</span>`;
  }

  // Processes
  if(procs.top){
    let p='<table><tr><th>User</th><th>PID</th><th>CPU%</th><th>Mem%</th><th>Command</th><th></th></tr>';
    procs.top.slice(0,20).forEach(pr=>{const susp=(procs.suspicious||[]).some(s=>s.pid===pr.pid);p+=`<tr style="${susp?'color:var(--red)':''}"><td>${h(pr.user)}</td><td>${h(pr.pid)}</td><td>${h(pr.cpu)}</td><td>${h(pr.mem)}</td><td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px">${h(pr.cmd)}</td><td>${susp||parseFloat(pr.cpu)>80?`<button class="btn btn-sm btn-red" onclick="killProc('${pr.pid}',this)">Kill</button>`:''}</td></tr>`;});
    p+='</table>';$('#proc-body').innerHTML=p;$('#proc-count').textContent=`${procs.top.length} procs`;
  }

  // Network
  if(net.outbound){
    let n='<table><tr><th>Proto</th><th>Local</th><th>Remote</th><th>Process</th></tr>';
    (net.outbound||[]).slice(0,20).forEach(c=>{n+=`<tr><td>${h(c.proto)}</td><td style="font-family:monospace;font-size:11px">${h(c.local)}</td><td style="font-family:monospace;font-size:11px">${h(c.remote)}</td><td>${h(c.process)}</td></tr>`;});
    n+='</table>';$('#net-body').innerHTML=n;$('#net-count').textContent=`${net.outbound.length} outbound`;
  }

  // Services — with CIS-aware disable buttons
  if(svcs.not_scanned){$('#svc-body').innerHTML='<div style="color:var(--orange);padding:12px;text-align:center">⚠ Requires sudo — not scanned</div>';$('#svc-count').textContent='N/A';}
  else if(svcs.enabled){
    const risky=new Set(svcs.risky||[]);
    const details=svcs.risky_details||[];
    const detailMap={};details.forEach(d=>{detailMap[d.name]=d;});
    let s='<div style="display:flex;flex-wrap:wrap;gap:4px">';
    svcs.enabled.forEach(sv=>{
      const r=risky.has(sv);
      const d=detailMap[sv];
      const roleExp=d&&d.role_expected;
      const fwBlocked=d&&d.firewalled;
      const badge=r?(fwBlocked?'badge-med':'badge-high'):roleExp?'badge-med':'badge-info';
      const fwTag=fwBlocked?' 🛡':'';
      const title=d?`${d.cis||''} ${d.reason||''}${fwBlocked?' [port blocked by firewall — reduced risk]':''}`.trim():'';
      s+=`<span class="badge ${badge}" style="margin:1px;cursor:${r?'pointer':'default'}" ${r?`onclick="disableSvc('${sv}',this)"`:''}${title?` title="${h(title)}"`:''}>${h(sv)}${r?' ✕':''}${fwTag}${roleExp?' ⓘ':''}</span>`;
    });
    s+='</div>';$('#svc-body').innerHTML=s;$('#svc-count').textContent=`${svcs.enabled.length} enabled`;
  }

  // Cron — with remove buttons for suspicious
  if(data.cron){
    const jobs=data.cron.jobs||[];
    const suspCron=['curl','wget','nc ','bash -i','/dev/tcp','base64'];
    if(jobs.length){let c='<table><tr><th>Source</th><th>Job</th><th></th></tr>';jobs.forEach(j=>{const isSusp=suspCron.some(s=>j.line.toLowerCase().includes(s));c+=`<tr><td><span class="badge badge-info">${h(j.source)}</span></td><td style="font-family:monospace;font-size:11px;word-break:break-all${isSusp?';color:var(--red)':''}">${h(j.line)}</td><td>${isSusp?`<button class="btn btn-sm btn-red" onclick="removeCron('${j.source}','${j.line.replace(/'/g,"\\'").replace(/"/g,'')}',this)">Disable</button>`:''}</td></tr>`;});c+='</table>';$('#cron-body').innerHTML=c;}
    else $('#cron-body').innerHTML='<span class="loading">No scheduled tasks</span>';
    $('#cron-count').textContent=`${jobs.length} jobs`;
  }

  // Kernel
  if(kern.not_scanned){$('#kernel-body').innerHTML='<div style="color:var(--orange);padding:12px;text-align:center">⚠ Requires sudo — not scanned</div>';}
  else if(kern.settings){
    let k='<table><tr><th>Setting</th><th>Value</th><th>Expected</th><th>Status</th></tr>';
    (kern.settings||[]).forEach(s=>{k+=`<tr><td style="font-family:monospace;font-size:11px">${h(s.key)}</td><td>${h(s.value)}</td><td style="color:var(--dim)">${h(s.expected||'')}</td><td><span class="badge ${s.ok?'badge-ok':'badge-med'}">${s.ok?'OK':s.cis_ref||'Issue'}</span></td></tr>`;});
    k+='</table>';$('#kernel-body').innerHTML=k;
  }

  // Login history
  if(data.users&&data.users.last_logins){
    let l='<table><tr><th>Login Entry</th></tr>';
    data.users.last_logins.forEach(ll=>{l+=`<tr><td style="font-family:monospace;font-size:11px">${h(ll)}</td></tr>`;});
    l+='</table>';$('#login-body').innerHTML=l;
  }

  // Findings
  const sevOrder={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3};
  const sorted=[...findings].sort((a,b)=>(sevOrder[a.sev]||9)-(sevOrder[b.sev]||9));
  let fhtml='';
  sorted.forEach(f=>{
    const bc={CRITICAL:'badge-crit',HIGH:'badge-high',MEDIUM:'badge-med',LOW:'badge-low'}[f.sev]||'badge-info';
    fhtml+=`<div class="finding"><div style="display:flex;justify-content:space-between;align-items:start"><div><span class="badge ${bc}">${f.sev}</span> <span class="finding-title">${h(f.title)}</span>${f.cis_ref?` <span style="color:var(--dim);font-size:10px">[${h(f.cis_ref)}]</span>`:''}${f.fixed?' <span class="badge badge-ok">FIXED</span>':''}</div>${f.fix_cmd&&!f.fixed?`<button class="btn btn-sm btn-cyan" onclick="fixOne(${f.id})">Fix</button>`:''}</div><div class="finding-detail">${h(f.detail)}</div>${f.fix_cmd?`<div class="finding-fix">${h(f.fix_cmd)}</div>`:''}</div>`;
  });
  $('#findings-body').innerHTML=fhtml||'<span class="loading">No findings yet</span>';
  $('#findings-count').textContent=`${findings.length} findings`;
  const unfixed=findings.filter(f=>!f.fixed).length;
  const tfc=$('#tab-findings-count');if(tfc)tfc.textContent=unfixed||'';

  // Actions
  let act='';
  if((d.actions||[]).length){act='<table><tr><th>Time</th><th>Action</th><th>Status</th><th></th></tr>';
    d.actions.forEach(a=>{act+=`<tr><td style="color:var(--dim)">${h(a.ts)}</td><td>${h(a.desc)}</td><td>${a.undone?'<span class="badge badge-med">Undone</span>':'<span class="badge badge-ok">Done</span>'}</td><td>${a.undo_cmd&&!a.undone?`<button class="btn btn-sm btn-ghost" onclick="undoAction(${a.id})">Undo</button>`:''}</td></tr>`;});
    act+='</table>';}else act='<span class="loading">No actions yet</span>';
  $('#actions-body').innerHTML=act;
}

function renderLog(d) {
  const el=$('#log-body');
  if(!el||!d.log) return;
  let l='';d.log.forEach(e=>{
    const c=e.msg.includes('✓')?'var(--green)':e.msg.includes('✗')?'var(--red)':e.msg.includes('▶')?'var(--cyan)':e.msg.includes('⚠')?'var(--yellow)':'var(--dim)';
    l+=`<div style="color:${c}"><span style="color:var(--dim);margin-right:8px">${h(e.ts)}</span>${h(e.msg)}</div>`;
  });
  el.innerHTML=l;el.scrollTop=el.scrollHeight;
  const lc=$('#log-count');if(lc)lc.textContent=d.log.length+' entries';
}

function card(label,val,color,sub){return `<div class="card"><div class="card-label">${label}</div><div class="card-val" style="color:var(--${color})">${val}</div><div class="card-sub">${sub}</div></div>`;}

function rescan(){fetch('/api/scan',{method:'POST'});}

function goSettings() {
  // Pre-fill login form with current values from state
  $('#dashboard').style.display = 'none';
  $('#login-page').style.display = 'flex';
  // Reset button state (may be stuck from previous connect)
  const btn = $('#btn-connect');
  btn.disabled = false;
  btn.textContent = '▶ Apply & Rescan';
  $('#login-status').style.display = 'none';
  $('#login-error').style.display = 'none';
  // Add a back button if not already there
  if (!$('#btn-back-dash')) {
    const back = document.createElement('button');
    back.id = 'btn-back-dash';
    back.className = 'btn-connect';
    back.style.cssText = 'background:var(--bg3);color:var(--text);border:1px solid var(--border);margin-top:6px';
    back.textContent = '← Back to Dashboard';
    back.onclick = function(){ backToDashboard(); };
    btn.parentNode.insertBefore(back, btn.nextSibling);
  }
}

function backToDashboard() {
  $('#login-page').style.display = 'none';
  $('#dashboard').style.display = 'flex';
  // Reset button text
  const btn = $('#btn-connect');
  btn.textContent = '▶ Launch Dashboard';
  btn.disabled = false;
}
function extScan(){
  const host = SSH_CONN_HOST || (D && D.data ? (D.data.hostname || '') : '');
  const target = prompt('External scan target (IP or hostname):', host);
  if (!target) return;
  EXT_STATE_LOADED=true;
  // Switch to external tab
  switchTab('external',document.querySelectorAll('.tab')[1]);
  fetch('/api/external-scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({host:target})}).then(()=>pollExt());
}
let extPolling=false;
function pollExt(){
  if(extPolling)return; extPolling=true;
  (function ep(){
    fetch('/api/external-state').then(r=>r.json()).then(d=>{
      renderExt(d);
      if(d.scanning) setTimeout(ep,800); else extPolling=false;
    }).catch(()=>{extPolling=false;});
  })();
}
function renderExt(d){
  const el=$('#ext-body');
  if(!el) return;
  const r=d.results||{};
  if(d.scanning){$('#ext-status').innerHTML=`<span style="color:var(--cyan)">${d.progress}%</span>`;}
  else if(r.score!=null){$('#ext-status').innerHTML=`<span class="badge ${r.score>=80?'badge-ok':r.score>=60?'badge-med':'badge-crit'}">Score: ${r.score}/100</span>`;}

  let html='';
  // Open ports
  if(r.open_ports){
    html+=`<div style="margin-bottom:12px"><b>Open Ports</b> (${r.open_ports.length}/${r.total_scanned} scanned)<table><tr><th>Port</th><th>Service</th><th>Banner</th><th></th></tr>`;
    r.open_ports.forEach(p=>{
      const danger=[21,23,25,110,111,135,139,445,1433,3306,3389,5432,5900,6379,9200,11211,27017].includes(p.port);
      html+=`<tr><td style="font-weight:700;color:${danger?'var(--red)':'var(--cyan)'}">${p.port}</td><td>${h(p.service)}</td><td style="font-family:monospace;font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis">${h(p.banner)}</td><td>${danger?`<button class="btn btn-sm btn-red" onclick="extBlock(${p.port})">Block</button>`:''}</td></tr>`;
    });
    html+='</table></div>';
  }
  // HTTP headers
  if(r.http&&r.http.available){
    html+=`<div style="margin-bottom:12px"><b>HTTP Security Headers</b> (server: ${h(r.http.server)})<table><tr><th>Header</th><th>Status</th><th>Value</th></tr>`;
    (r.http.checks||[]).forEach(c=>{
      html+=`<tr><td>${h(c.header)}</td><td><span class="badge ${c.present?'badge-ok':'badge-high'}">${c.present?'Present':'MISSING'}</span></td><td style="font-size:11px;max-width:200px;overflow:hidden">${h(c.value||'')}</td></tr>`;
    });
    html+='</table></div>';
  }
  // SSL
  if(r.ssl&&r.ssl.available){
    html+=`<div style="margin-bottom:12px"><b>SSL/TLS</b>: ${h(r.ssl.version)} | Expires: ${r.ssl.expires_days} days | Subject: ${h((r.ssl.subject||{}).commonName||'?')}</div>`;
  }
  // SSH banner
  if(r.ssh_banner&&r.ssh_banner.banner){
    html+=`<div style="margin-bottom:12px"><b>SSH Banner</b>: <code>${h(r.ssh_banner.banner)}</code></div>`;
  }
  // Findings
  if(r.findings&&r.findings.length){
    html+=`<div style="margin-top:8px"><b>Findings (${r.findings.length})</b></div>`;
    r.findings.forEach((f,i)=>{
      const bc={CRITICAL:'badge-crit',HIGH:'badge-high',MEDIUM:'badge-med',LOW:'badge-low'}[f.sev]||'badge-info';
      html+=`<div class="finding"><span class="badge ${bc}">${f.sev}</span> <span class="finding-title">${h(f.title)}</span>${f.fixed?' <span class="badge badge-ok">FIXED</span>':''}${f.fix_cmd&&!f.fixed?` <button class="btn btn-sm btn-cyan" onclick="extFix(${i})">Fix</button>`:''}<div class="finding-detail">${h(f.detail)}</div>${f.fix_cmd?`<div class="finding-fix">${h(f.fix_cmd)}</div>`:''}</div>`;
    });
  }
  // Log
  if(d.log&&d.log.length){
    html+=`<div style="margin-top:10px;border-top:1px solid var(--border);padding-top:8px;font-family:monospace;font-size:11px;max-height:150px;overflow-y:auto">`;
    d.log.forEach(l=>{
      const c=l.msg.includes('✓')?'var(--green)':l.msg.includes('⚠')?'var(--yellow)':l.msg.includes('▶')?'var(--cyan)':'var(--dim)';
      html+=`<div style="color:${c}">${h(l.ts)} ${h(l.msg)}</div>`;
    });
    html+='</div>';
  }
  if(!html&&d.scanning) html='<span class="loading">Scanning external exposure...</span>';
  if(html) el.innerHTML=html;
}
function extBlock(port){fetch('/api/ext-fix',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({index:-1})});fetch('/api/block-ip',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({port})}).catch(()=>{});const s=SSH_CONN_HOST;if(s)fetch('/api/fix',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({cmd:`sudo ufw deny ${port}/tcp`})}).catch(()=>{});alert(`Block port ${port}: use the Fix button on the finding to apply via SSH`);}
function extFix(idx){fetch('/api/ext-fix',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({index:idx})}).then(r=>r.json()).then(d=>{if(d.success)pollExt();else alert('Fix failed: '+(d.output||'unknown error'));});}
let SSH_CONN_HOST='';
function fixOne(id){const btn=event.target;btn.disabled=true;btn.textContent='...';fetch('/api/fix',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})}).then(r=>r.json()).then(d=>{btn.textContent=d.success?'✓':'✗';if(!d.success)setTimeout(()=>{btn.disabled=false;btn.textContent='Fix';},2000);}).catch(()=>{btn.textContent='✗ Error';setTimeout(()=>{btn.disabled=false;btn.textContent='Fix';},2000);});}
function fixAll(){fetch('/api/fix-all',{method:'POST'}).then(()=>setTimeout(poll,500));}
function blockIP(ip,btn){if(btn){btn.disabled=true;btn.textContent='Blocking...';}fetch('/api/block-ip',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})}).then(r=>r.json()).then(d=>{if(btn){btn.textContent=d.success?'✓ Blocked':'✗ '+(d.error||'Failed');if(d.success){btn.className='btn btn-sm badge-ok';btn.style.color='var(--green)';}}if(d.success&&D&&D.data&&D.data.logs){const a=(D.data.logs.attackers||[]).find(x=>x.ip===ip);if(a)a.blocked=true;}setTimeout(poll,2500);}).catch(()=>{if(btn){btn.textContent='✗ Error';setTimeout(()=>{btn.disabled=false;btn.textContent='Block';},2000);}});}
function blockAttackers(){const btn=event.target;btn.disabled=true;btn.textContent='Blocking...';fetch('/api/block-attackers',{method:'POST'}).then(r=>r.json()).then(d=>{btn.textContent=`✓ ${d.blocked} blocked`;setTimeout(()=>{btn.disabled=false;btn.textContent='Block Top 10 Unblocked';poll();},3000);}).catch(()=>{btn.textContent='✗ Error';setTimeout(()=>{btn.disabled=false;btn.textContent='Block Top 10 Unblocked';},2000);});}
function undoAction(id){fetch('/api/undo',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})}).then(()=>setTimeout(poll,500));}
function killProc(pid,btn){if(!confirm('Kill PID '+pid+'?'))return;btn.disabled=true;btn.textContent='...';fetch('/api/kill-process',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pid})}).then(r=>r.json()).then(d=>{btn.textContent=d.success?'Killed':'Failed';if(!d.success)setTimeout(()=>{btn.disabled=false;btn.textContent='Kill';},2000);}).catch(()=>{btn.textContent='✗ Error';setTimeout(()=>{btn.disabled=false;btn.textContent='Kill';},2000);});}
function hardenF2b(btn){if(!confirm('Apply strict fail2ban config?\n\n• Ban time: 24 hours (was ~10 min)\n• Max retries: 3 (was 5)\n• Find window: 1 hour\n• Escalating bans for repeat offenders\n• Max ban: 7 days'))return;btn.disabled=true;btn.textContent='Applying...';fetch('/api/harden-f2b',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({})}).then(r=>r.json()).then(d=>{if(d.success){btn.textContent='✓ Hardened';btn.className='btn btn-sm btn-ghost';setTimeout(()=>rescan(),1000);}else{btn.textContent='Failed';btn.disabled=false;alert('Error: '+(d.output||'unknown'));}}).catch(()=>{btn.textContent='✗ Error';btn.disabled=false;});}
function disableSvc(name,el){if(!confirm('Disable and stop service: '+name+'?'))return;el.style.opacity=0.5;fetch('/api/disable-service',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({service:name})}).then(r=>r.json()).then(d=>{if(d.success){el.className='badge badge-ok';el.textContent=name+' ✓';el.style.opacity=1;}else{el.style.opacity=1;alert('Failed: '+(d.output||''));}}).catch(()=>{el.style.opacity=1;});}
function removeCron(source,line,btn){if(!confirm('Disable this cron job?'))return;btn.disabled=true;btn.textContent='...';fetch('/api/remove-cron',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({source,line})}).then(r=>r.json()).then(d=>{btn.textContent=d.success?'Disabled':'Failed';if(!d.success)setTimeout(()=>{btn.disabled=false;btn.textContent='Disable';},2000);}).catch(()=>{btn.textContent='✗ Error';setTimeout(()=>{btn.disabled=false;btn.textContent='Disable';},2000);});}
function stopServer(){if(!confirm('Stop the AEGIS server process? You will need to rerun the script to restart.'))return;fetch('/api/shutdown',{method:'POST'}).then(()=>{document.body.innerHTML='<div style="display:flex;align-items:center;justify-content:center;height:100vh;color:#fff;font-family:system-ui"><div style="text-align:center"><h2>◆ AEGIS Stopped</h2><p style="color:#8892b0">Server process terminated. Close this tab.</p></div></div>';}).catch(()=>{});}

// ═══════ UFW Management ═══════
function ufwRefresh(){
  $('#ufw-mgmt-body').innerHTML='<span class="loading">Loading UFW status...</span>';
  fetch('/api/manage/ufw/status').then(r=>r.json()).then(d=>{
    if(d.error){$('#ufw-mgmt-body').innerHTML=`<div style="color:var(--red);padding:12px">${h(d.error)}</div>`;return;}
    renderUfwPanel(d);
  }).catch(e=>{$('#ufw-mgmt-body').innerHTML=`<div style="color:var(--red);padding:12px">Error: ${e}</div>`;});
}

function renderUfwPanel(d){
  let s='';
  // Status bar
  if(!d.installed){
    $('#ufw-mgmt-status').innerHTML='<span class="mgmt-tag off">Not Installed</span>';
    s+=`<div style="text-align:center;padding:30px"><div style="font-size:36px;margin-bottom:12px">🛡</div>
      <div style="color:var(--dim);margin-bottom:16px">UFW is not installed on this server</div>
      <button class="btn btn-cyan" onclick="ufwAction('/api/manage/ufw/install','Installing UFW...')">Install UFW</button></div>`;
    $('#ufw-mgmt-body').innerHTML=s;return;
  }
  const active=d.active;
  $('#ufw-mgmt-status').innerHTML=active?'<span class="mgmt-tag on">● Active</span>':'<span class="mgmt-tag off">● Inactive</span>';

  // Controls
  s+=`<div class="mgmt-controls" style="padding:10px 12px;border-bottom:1px solid var(--border)">`;
  if(active){
    s+=`<button class="btn btn-sm btn-red" onclick="if(confirm('Disable firewall? All ports will be exposed.'))ufwAction('/api/manage/ufw/disable','Disabling...')">⏻ Disable UFW</button>`;
  }else{
    s+=`<button class="btn btn-sm btn-green" onclick="ufwAction('/api/manage/ufw/enable','Enabling...')">⏻ Enable UFW</button>`;
  }
  s+=`<span style="color:var(--dim);font-size:12px;margin-left:8px">Default incoming: </span>`;
  s+=`<select id="ufw-default-in" onchange="ufwSetDefault('incoming',this.value)" style="background:var(--bg);color:var(--text);border:1px solid var(--border);padding:3px 8px;border-radius:4px;font-size:12px">`;
  ['deny','allow','reject'].forEach(p=>{s+=`<option value="${p}"${d.default_in===p?' selected':''}>${p}</option>`;});
  s+=`</select>`;
  s+=`<span style="color:var(--dim);font-size:12px;margin-left:8px">Default outgoing: </span>`;
  s+=`<select id="ufw-default-out" onchange="ufwSetDefault('outgoing',this.value)" style="background:var(--bg);color:var(--text);border:1px solid var(--border);padding:3px 8px;border-radius:4px;font-size:12px">`;
  ['allow','deny','reject'].forEach(p=>{s+=`<option value="${p}"${d.default_out===p?' selected':''}>${p}</option>`;});
  s+=`</select>`;
  s+=`</div>`;

  // Add Rule form
  s+=`<div class="mgmt-form">
    <label>Port<input id="ufw-port" placeholder="80 or 8000:8100" style="width:110px"></label>
    <label>Protocol<select id="ufw-proto"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="both">Both</option></select></label>
    <label>Action<select id="ufw-action"><option value="allow">Allow</option><option value="deny">Deny</option><option value="reject">Reject</option><option value="limit">Limit</option></select></label>
    <label>From IP <span style="font-size:10px;color:var(--dim)">(optional)</span><input id="ufw-from" placeholder="any" style="width:130px"></label>
    <label>Comment <span style="font-size:10px;color:var(--dim)">(optional)</span><input id="ufw-comment" placeholder="" style="width:130px"></label>
    <button class="btn btn-sm btn-cyan" style="align-self:end" onclick="ufwAddRule()">+ Add Rule</button>
  </div>`;

  // Quick-add common ports
  s+=`<div style="padding:6px 12px;display:flex;flex-wrap:wrap;gap:4px;border-bottom:1px solid var(--border)">
    <span style="color:var(--dim);font-size:11px;margin-right:4px;line-height:24px">Quick:</span>`;
  const quick=[{l:'SSH :22',p:'22',pr:'tcp'},{l:'HTTP :80',p:'80',pr:'tcp'},{l:'HTTPS :443',p:'443',pr:'tcp'},
    {l:'PostgreSQL :5432',p:'5432',pr:'tcp'},{l:'MySQL :3306',p:'3306',pr:'tcp'},{l:'Redis :6379',p:'6379',pr:'tcp'},
    {l:'DNS :53',p:'53',pr:'both'},{l:'SMTP :25',p:'25',pr:'tcp'}];
  const allowed=new Set((d.rules||[]).map(r=>{const m=r.rule.match(/^(\d+)/);return m?m[1]:'';}));
  quick.forEach(q=>{
    const exists=d.rules&&d.rules.some(r=>r.rule.includes(q.p));
    s+=`<button class="btn btn-sm ${exists?'btn-ghost':'btn-cyan'}" style="padding:2px 8px;font-size:11px" onclick="ufwQuick('${q.p}','${q.pr}')" ${exists?'disabled':''}>${q.l}${exists?' ✓':''}</button>`;
  });
  s+=`</div>`;

  // Block IP form
  s+=`<div style="padding:8px 12px;display:flex;align-items:center;gap:8px;border-bottom:1px solid var(--border)">
    <span style="color:var(--dim);font-size:12px">Block IP:</span>
    <input id="ufw-block-ip" placeholder="192.168.1.100 or 10.0.0.0/8" style="background:var(--bg);color:var(--text);border:1px solid var(--border);padding:4px 8px;border-radius:4px;font-size:12px;width:180px">
    <button class="btn btn-sm btn-red" onclick="ufwBlockIP()">Block</button>
  </div>`;

  // Rules list
  s+=`<div style="padding:8px 12px 4px"><span style="font-size:12px;font-weight:600;color:var(--dim)">${(d.rules||[]).length} Rules</span></div>`;
  if(d.rules&&d.rules.length){
    d.rules.forEach(r=>{
      const isAllow=r.rule.includes('ALLOW');
      const isDeny=r.rule.includes('DENY');
      const isLimit=r.rule.includes('LIMIT');
      const cls=isAllow?'rule-allow':isDeny?'rule-deny':isLimit?'rule-limit':'';
      const isSSH=r.rule.includes('22')&&isAllow;
      s+=`<div class="mgmt-rule"><span class="rule-num">[${r.num}]</span><span class="rule-text ${cls}">${h(r.rule)}</span>`;
      s+=`<button class="btn btn-sm btn-red" style="padding:1px 8px;font-size:11px" onclick="ufwDeleteRule(${r.num},${isSSH})" title="Delete rule">✕</button>`;
      s+=`</div>`;
    });
  }else{
    s+=`<div style="color:var(--dim);padding:12px;text-align:center">No rules configured</div>`;
  }

  $('#ufw-mgmt-body').innerHTML=s;
}

function ufwAction(url,msg){
  const body=$('#ufw-mgmt-body');
  body.innerHTML=`<span class="loading">${msg}</span>`;
  fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).then(r=>r.json()).then(d=>{
    setTimeout(ufwRefresh,500);
  }).catch(()=>{body.innerHTML='<div style="color:var(--red);padding:12px">Action failed</div>';});
}

function ufwSetDefault(dir,policy){
  fetch('/api/manage/ufw/default',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({direction:dir,policy:policy})}).then(r=>r.json()).then(d=>{setTimeout(ufwRefresh,500);});
}

function ufwAddRule(){
  const port=$('#ufw-port').value.trim();
  if(!port){alert('Enter a port number');return;}
  const data={port:port,proto:$('#ufw-proto').value,action:$('#ufw-action').value,from_ip:$('#ufw-from').value.trim(),comment:$('#ufw-comment').value.trim()};
  fetch('/api/manage/ufw/add-rule',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)}).then(r=>r.json()).then(d=>{
    if(d.error)alert(d.error);
    else{$('#ufw-port').value='';$('#ufw-from').value='';$('#ufw-comment').value='';setTimeout(ufwRefresh,500);}
  });
}

function ufwQuick(port,proto){
  fetch('/api/manage/ufw/add-rule',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({port:port,proto:proto,action:'allow'})}).then(r=>r.json()).then(()=>setTimeout(ufwRefresh,500));
}

function ufwDeleteRule(num,isSSH){
  if(isSSH&&!confirm('WARNING: This is an SSH rule. Deleting it may lock you out of the server. Continue?'))return;
  if(!isSSH&&!confirm('Delete this firewall rule?'))return;
  fetch('/api/manage/ufw/delete-rule',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({num:num})}).then(r=>r.json()).then(()=>setTimeout(ufwRefresh,500));
}

function ufwBlockIP(){
  const ip=$('#ufw-block-ip').value.trim();
  if(!ip){alert('Enter an IP address');return;}
  fetch('/api/manage/ufw/block-ip',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:ip})}).then(r=>r.json()).then(d=>{
    if(d.error)alert(d.error);
    else{$('#ufw-block-ip').value='';setTimeout(ufwRefresh,500);}
  });
}

// ═══════ LAN Scan ═══════
function lanScan(){
  const btn=$('#btn-lan-scan');
  btn.disabled=true;btn.textContent='Scanning...';
  const subnet=$('#lan-subnet').value.trim();
  const portscan=$('#lan-portscan').value;
  fetch('/api/lan-scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({subnet,portscan})})
    .then(r=>r.json()).then(d=>{
      if(d.error){alert(d.error);btn.disabled=false;btn.textContent='▶ Scan LAN';return;}
      pollLan();
    }).catch(e=>{alert('Error: '+e);btn.disabled=false;btn.textContent='▶ Scan LAN';});
}

function pollLan(){
  fetch('/api/lan-state').then(r=>r.json()).then(d=>{
    const btn=$('#btn-lan-scan');
    if(d.scanning){
      $('#lan-status').innerHTML=`<span style="color:var(--cyan)">Scanning... ${d.progress}%</span>`;
      setTimeout(pollLan,1500);
    }else{
      btn.disabled=false;btn.textContent='▶ Scan LAN';
      if(d.error){
        $('#lan-status').innerHTML=`<span style="color:var(--red)">${h(d.error)}</span>`;
      }else if((d.hosts||[]).length){
        $('#lan-status').innerHTML=`<span style="color:var(--green)">${(d.hosts||[]).length} hosts</span>`;
      }
      renderLanResults(d);
    }
  }).catch(()=>setTimeout(pollLan,2000));
}

function renderLanResults(d){
  const hosts=d.hosts||[];
  const findings=d.findings||[];
  const summary=d.summary||{};
  const net=d.network_info||{};
  const rs=$('#lan-results-section');
  const rb=$('#lan-results');
  if(hosts.length){
    rs.style.display='block';
    $('#lan-host-count').textContent=hosts.length+' hosts on '+(d.subnet||'LAN');
    // Summary bar
    let sm='<div style="display:flex;gap:16px;padding:10px 8px;border-bottom:1px solid var(--border);font-size:12px;flex-wrap:wrap">';
    if(net.gateway) sm+=`<span>🌐 Gateway: <b>${h(net.gateway)}</b></span>`;
    if(net.dns&&net.dns.length) sm+=`<span>📡 DNS: <b>${net.dns.map(h).join(', ')}</b></span>`;
    sm+=`<span>🖥 ${summary.total_hosts||0} hosts</span>`;
    sm+=`<span>🔌 ${summary.total_open_ports||0} open ports</span>`;
    if(summary.hosts_with_http) sm+=`<span>🌐 ${summary.hosts_with_http} web</span>`;
    if(summary.hosts_with_ssh) sm+=`<span>🔑 ${summary.hosts_with_ssh} SSH</span>`;
    if(summary.hosts_with_smb) sm+=`<span>📁 ${summary.hosts_with_smb} SMB</span>`;
    if(summary.hosts_with_db) sm+=`<span>🗄 ${summary.hosts_with_db} databases</span>`;
    sm+='</div>';
    // Host table
    let ht=sm+'<table style="width:100%;font-size:12px;border-collapse:collapse">';
    ht+='<tr style="color:var(--dim);text-align:left;border-bottom:1px solid var(--border)"><th style="padding:6px 8px">IP</th><th style="padding:6px 8px">Hostname</th><th style="padding:6px 8px">MAC</th><th style="padding:6px 8px">Ports</th><th style="padding:6px 8px">Services</th></tr>';
    hosts.forEach(host=>{
      const row_style=host.is_self?'color:var(--cyan)':host.is_gateway?'color:var(--orange)':'';
      let badges='';
      if(host.is_self) badges+=' <span class="mgmt-tag info" style="font-size:9px">YOU</span>';
      if(host.is_gateway) badges+=' <span class="mgmt-tag on" style="font-size:9px">GATEWAY</span>';
      const pc=host.port_count>10?'var(--red)':host.port_count>5?'var(--yellow)':host.port_count>0?'var(--text)':'var(--dim)';
      const svcs=host.services.map(s=>{
        let color=s.port===22||s.port===80||s.port===443?'on':s.port===23||s.port===21?'off':'info';
        let tip=s.version?` title="${h(s.version)}"`:s.banner?` title="${h(s.banner.substring(0,60))}"`:' ';
        return `<span class="mgmt-tag ${color}" style="font-size:10px;margin:1px;cursor:default"${tip}>${s.service}:${s.port}</span>`;
      }).join(' ');
      ht+=`<tr style="border-bottom:1px solid var(--border);${row_style}"><td style="padding:6px 8px;font-family:monospace">${h(host.ip)}${badges}</td><td style="padding:6px 8px">${h(host.hostname||'—')}</td><td style="padding:6px 8px;font-family:monospace;font-size:11px;color:var(--dim)">${h(host.mac||'—')}</td><td style="padding:6px 8px;color:${pc}">${host.port_count}</td><td style="padding:6px 8px">${svcs||'<span style="color:var(--dim)">none</span>'}</td></tr>`;
    });
    ht+='</table>';
    rb.innerHTML=ht;
  }else{rs.style.display='none';}

  const fs=$('#lan-findings-section');
  const fb=$('#lan-findings');
  if(findings.length){
    fs.style.display='block';
    let cnt_html=`${findings.length} issues`;
    if(summary.findings_high) cnt_html+=` <span class="badge badge-high" style="font-size:10px">${summary.findings_high} HIGH</span>`;
    if(summary.findings_medium) cnt_html+=` <span class="badge badge-med" style="font-size:10px">${summary.findings_medium} MED</span>`;
    $('#lan-finding-count').innerHTML=cnt_html;
    let ft='';
    findings.forEach(f=>{
      const bc=f.sev==='HIGH'?'badge-high':f.sev==='CRITICAL'?'badge-crit':f.sev==='LOW'||f.sev==='INFO'?'badge-ok':'badge-med';
      ft+=`<div class="finding"><span class="badge ${bc}">${f.sev}</span> <span class="finding-title">${h(f.title)}</span><div class="finding-detail">${h(f.detail)}</div></div>`;
    });
    fb.innerHTML=ft;
  }else if(hosts.length){
    fs.style.display='block';
    $('#lan-finding-count').textContent='0 issues';
    fb.innerHTML='<div style="color:var(--green);padding:12px">✓ No security issues detected on LAN hosts</div>';
  }else{fs.style.display='none';}
}

// ═══════ Fail2ban Management ═══════
function f2bRefresh(){
  $('#f2b-mgmt-body').innerHTML='<span class="loading">Loading fail2ban status...</span>';
  fetch('/api/manage/f2b/status').then(r=>r.json()).then(d=>{
    if(d.error){$('#f2b-mgmt-body').innerHTML=`<div style="color:var(--red);padding:12px">${h(d.error)}</div>`;return;}
    renderF2bPanel(d);
  }).catch(e=>{$('#f2b-mgmt-body').innerHTML=`<div style="color:var(--red);padding:12px">Error: ${e}</div>`;});
}

function renderF2bPanel(d){
  if(!d.installed){
    $('#f2b-mgmt-status').innerHTML='<span class="mgmt-tag off">Not Installed</span>';
    $('#f2b-mgmt-body').innerHTML='<div style="text-align:center;color:var(--dim);padding:20px">Fail2ban is not installed</div>';
    return;
  }
  $('#f2b-mgmt-status').innerHTML=d.running?'<span class="mgmt-tag on">● Running</span>':'<span class="mgmt-tag off">● Stopped</span>';
  let s='';

  // Banned IPs
  s+=`<div style="padding:10px 12px;border-bottom:1px solid var(--border)">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
      <span style="font-weight:600;font-size:13px;color:${d.banned.length?'var(--red)':'var(--green)'}">
        ${d.banned.length?'🚫 '+d.banned.length+' Banned IPs':'✓ No banned IPs'}</span>
      ${d.banned.length?'<button class="btn btn-sm btn-red" onclick="f2bUnbanAll()">Unban All</button>':''}
    </div>`;
  if(d.banned.length){
    d.banned.forEach(ip=>{
      s+=`<div class="mgmt-rule"><span class="rule-text rule-deny" style="font-family:monospace">${h(ip)}</span>
        <button class="btn btn-sm btn-cyan" style="padding:1px 8px;font-size:11px" onclick="f2bUnban('${ip}')">Unban</button>
        <button class="btn btn-sm btn-green" style="padding:1px 8px;font-size:11px" onclick="f2bWhitelist('${ip}')" title="Permanently whitelist">Whitelist</button></div>`;
    });
  }
  s+=`</div>`;

  // Whitelist IP form
  s+=`<div style="padding:8px 12px;display:flex;align-items:center;gap:8px;border-bottom:1px solid var(--border)">
    <span style="color:var(--dim);font-size:12px">Whitelist IP:</span>
    <input id="f2b-wl-ip" placeholder="IP or CIDR (e.g., 10.0.0.0/8)" style="background:var(--bg);color:var(--text);border:1px solid var(--border);padding:4px 8px;border-radius:4px;font-size:12px;width:180px">
    <button class="btn btn-sm btn-green" onclick="f2bWhitelistInput()">+ Whitelist</button>
  </div>`;

  // Current whitelist
  if(d.whitelist&&d.whitelist.length){
    s+=`<div style="padding:8px 12px;border-bottom:1px solid var(--border)"><span style="font-size:12px;color:var(--dim)">Whitelisted: </span>`;
    d.whitelist.forEach(ip=>{s+=`<span class="mgmt-tag on" style="margin:2px">${h(ip)}</span>`;});
    s+=`</div>`;
  }

  // SSHD settings
  if(d.sshd_settings && d.sshd_settings!=='DEFAULTS'){
    s+=`<div style="padding:8px 12px;font-size:12px;color:var(--dim);border-bottom:1px solid var(--border)">
      <span style="font-weight:600">sshd_config: </span><span style="font-family:monospace">${h(d.sshd_settings)}</span></div>`;
  }else{
    s+=`<div style="padding:8px 12px;font-size:12px;color:var(--dim)">
      <span style="font-weight:600">sshd_config: </span>Using defaults (MaxStartups 10:30:100, MaxSessions 10, LoginGraceTime 120s)</div>`;
  }

  $('#f2b-mgmt-body').innerHTML=s;
}

function f2bUnban(ip){
  fetch('/api/manage/f2b/unban',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:ip})}).then(r=>r.json()).then(()=>setTimeout(f2bRefresh,500));
}
function f2bUnbanAll(){
  if(!confirm('Unban ALL IPs from fail2ban?'))return;
  fetch('/api/manage/f2b/unban-all',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).then(r=>r.json()).then(()=>setTimeout(f2bRefresh,500));
}
function f2bWhitelist(ip){
  fetch('/api/manage/f2b/whitelist',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:ip})}).then(r=>r.json()).then(()=>setTimeout(f2bRefresh,500));
}
function f2bWhitelistInput(){
  const ip=$('#f2b-wl-ip').value.trim();
  if(!ip){alert('Enter an IP address');return;}
  f2bWhitelist(ip);
  $('#f2b-wl-ip').value='';
}

// ═══════ Nginx Management ═══════
let _nginxData=null;

function nginxRefresh(){
  $('#nginx-mgmt-body').innerHTML='<span class="loading">Loading Nginx status...</span>';
  fetch('/api/manage/nginx/status').then(r=>r.json()).then(d=>{
    if(d.error){$('#nginx-mgmt-body').innerHTML=`<div style="color:var(--red);padding:12px">${h(d.error)}</div>`;return;}
    _nginxData=d;
    renderNginxPanel(d);
  }).catch(e=>{$('#nginx-mgmt-body').innerHTML=`<div style="color:var(--red);padding:12px">Error: ${e}</div>`;});
}

function renderNginxPanel(d){
  let s='';
  if(!d.installed){
    $('#nginx-mgmt-status').innerHTML='<span class="mgmt-tag off">Not Installed</span>';
    s+=`<div style="text-align:center;padding:30px"><div style="font-size:36px;margin-bottom:12px">🌐</div>
      <div style="color:var(--dim);margin-bottom:16px">Nginx is not installed on this server</div>
      <button class="btn btn-cyan" onclick="nginxInstall()">Install Nginx</button></div>`;
    $('#nginx-mgmt-body').innerHTML=s;return;
  }

  const active=d.active;
  $('#nginx-mgmt-status').innerHTML=`${active?'<span class="mgmt-tag on">● Running</span>':'<span class="mgmt-tag off">● Stopped</span>'} <span class="mgmt-tag info">${h(d.version||'')}</span> ${d.test_ok?'<span class="mgmt-tag on">Config OK</span>':'<span class="mgmt-tag off">Config Error</span>'}`;

  // Controls
  s+=`<div class="mgmt-controls" style="padding:10px 12px;border-bottom:1px solid var(--border)">`;
  if(active){
    s+=`<button class="btn btn-sm btn-red" onclick="nginxAction('stop')">⏹ Stop</button>`;
    s+=`<button class="btn btn-sm btn-cyan" onclick="nginxAction('restart')">⟳ Restart</button>`;
    s+=`<button class="btn btn-sm btn-cyan" onclick="nginxAction('reload')">↻ Reload</button>`;
  }else{
    s+=`<button class="btn btn-sm btn-green" onclick="nginxAction('start')">▶ Start</button>`;
  }
  s+=`<button class="btn btn-sm btn-cyan" style="margin-left:auto" onclick="showNewSiteForm()">+ New Site</button>`;
  s+=`</div>`;

  // New site form (hidden by default)
  s+=`<div id="nginx-new-site" style="display:none">
    <div class="mgmt-form" style="flex-direction:column;align-items:stretch">
      <div style="font-weight:600;font-size:13px;margin-bottom:4px">Create New Site</div>
      <div style="display:flex;flex-wrap:wrap;gap:8px">
        <label>Site Name<input id="nx-name" placeholder="myapp" style="width:120px"></label>
        <label>Domain<input id="nx-domain" placeholder="example.com or _" style="width:160px" value="_"></label>
        <label>Listen Port<input id="nx-port" placeholder="80" style="width:70px" value="80"></label>
        <label>Type<select id="nx-type" onchange="nxTypeChanged()"><option value="proxy">Reverse Proxy</option><option value="static">Static Files</option><option value="redirect">Redirect</option></select></label>
      </div>
      <div id="nx-proxy-fields" style="display:flex;flex-wrap:wrap;gap:8px;margin-top:4px">
        <label>Proxy Target<input id="nx-proxy" placeholder="http://127.0.0.1:3000" style="width:240px"></label>
      </div>
      <div id="nx-static-fields" style="display:none;flex-wrap:wrap;gap:8px;margin-top:4px">
        <label>Root Path<input id="nx-root" placeholder="/var/www/html" style="width:240px"></label>
      </div>
      <div id="nx-redirect-fields" style="display:none;flex-wrap:wrap;gap:8px;margin-top:4px">
        <label>Redirect URL<input id="nx-redirect" placeholder="https://example.com" style="width:240px"></label>
      </div>
      <div style="display:flex;gap:8px;margin-top:8px">
        <button class="btn btn-sm btn-cyan" onclick="nginxCreateSite()">Create Site</button>
        <button class="btn btn-sm btn-ghost" onclick="$('#nginx-new-site').style.display='none'">Cancel</button>
      </div>
    </div>
  </div>`;

  // Sites list
  s+=`<div style="padding:8px 12px 4px"><span style="font-size:12px;font-weight:600;color:var(--dim)">${(d.sites||[]).length} Sites</span></div>`;
  if(d.sites&&d.sites.length){
    d.sites.forEach((site,i)=>{
      s+=`<div class="site-card">
        <div class="site-card-head">
          <span class="site-name">${h(site.name)}</span>
          <span class="mgmt-tag ${site.enabled?'on':'off'}">${site.enabled?'enabled':'disabled'}</span>
          ${site.ssl?'<span class="mgmt-tag info">🔒 SSL</span>':''}
          <span style="color:var(--dim);font-size:11px">${h(site.server_name||'_')}</span>
          <span style="color:var(--dim);font-size:11px;font-family:monospace">${(site.listen||[]).map(h).join(', ')}</span>
          <div style="margin-left:auto;display:flex;gap:4px">
            <button class="btn btn-sm ${site.enabled?'btn-red':'btn-green'}" style="padding:1px 8px;font-size:11px" onclick="nginxToggleSite('${site.name}',${!site.enabled})">${site.enabled?'Disable':'Enable'}</button>
            <button class="btn btn-sm btn-cyan" style="padding:1px 8px;font-size:11px" onclick="nginxEditSite('${site.name}')">Edit</button>
            <button class="btn btn-sm btn-red" style="padding:1px 8px;font-size:11px" onclick="nginxDeleteSite('${site.name}')">✕</button>
          </div>
        </div>`;
      if(site.locations&&site.locations.length){
        s+=`<div class="site-locations">`;
        site.locations.forEach(loc=>{
          if(loc.type==='proxy')
            s+=`<div class="site-location">📍 ${h(loc.path)} → <span style="color:var(--cyan)">${h(loc.proxy_pass||'')}</span></div>`;
          else if(loc.root)
            s+=`<div class="site-location">📁 ${h(loc.path)} → ${h(loc.root)}</div>`;
          else
            s+=`<div class="site-location">📍 ${h(loc.path)} [${h(loc.type)}]</div>`;
        });
        s+=`</div>`;
      }
      s+=`</div>`;
    });
  }else{
    s+=`<div style="color:var(--dim);padding:12px;text-align:center">No sites configured</div>`;
  }

  // Config editor (hidden by default)
  s+=`<div id="nginx-editor" style="display:none;padding:12px">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
      <span style="font-weight:600;font-size:13px">Editing: <span id="nx-edit-name" style="color:var(--cyan)"></span></span>
      <button class="btn btn-sm btn-cyan" style="margin-left:auto" onclick="nginxSaveConfig()">Save & Reload</button>
      <button class="btn btn-sm btn-ghost" onclick="$('#nginx-editor').style.display='none'">Cancel</button>
    </div>
    <textarea id="nx-editor-text" class="config-editor" rows="15"></textarea>
  </div>`;

  $('#nginx-mgmt-body').innerHTML=s;
}

function showNewSiteForm(){$('#nginx-new-site').style.display='block';}
function nxTypeChanged(){
  const t=$('#nx-type').value;
  $('#nx-proxy-fields').style.display=t==='proxy'?'flex':'none';
  $('#nx-static-fields').style.display=t==='static'?'flex':'none';
  $('#nx-redirect-fields').style.display=t==='redirect'?'flex':'none';
}

function nginxInstall(){
  $('#nginx-mgmt-body').innerHTML='<span class="loading">Installing Nginx...</span>';
  fetch('/api/manage/nginx/install',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).then(r=>r.json()).then(d=>{
    setTimeout(nginxRefresh,500);
  }).catch(()=>{$('#nginx-mgmt-body').innerHTML='<div style="color:var(--red);padding:12px">Install failed</div>';});
}

function nginxAction(action){
  fetch('/api/manage/nginx/toggle',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:action})}).then(r=>r.json()).then(()=>setTimeout(nginxRefresh,500));
}

function nginxCreateSite(){
  const name=$('#nx-name').value.trim();
  if(!name){alert('Enter a site name');return;}
  const data={name:name,domain:$('#nx-domain').value.trim()||'_',listen_port:$('#nx-port').value.trim()||'80',
    type:$('#nx-type').value,proxy_target:$('#nx-proxy').value.trim(),root_path:$('#nx-root').value.trim(),redirect_url:$('#nx-redirect').value.trim()};
  fetch('/api/manage/nginx/create-site',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)}).then(r=>r.json()).then(d=>{
    if(d.error)alert(d.error);
    else{$('#nginx-new-site').style.display='none';setTimeout(nginxRefresh,500);}
  });
}

function nginxToggleSite(name,enable){
  fetch('/api/manage/nginx/toggle-site',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name,enable:enable})}).then(r=>r.json()).then(()=>setTimeout(nginxRefresh,500));
}

function nginxDeleteSite(name){
  if(!confirm(`Delete site "${name}"? This removes the config file.`))return;
  fetch('/api/manage/nginx/delete-site',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name})}).then(r=>r.json()).then(()=>setTimeout(nginxRefresh,500));
}

function nginxEditSite(name){
  fetch(`/api/manage/nginx/get-site-config?name=${encodeURIComponent(name)}`).then(r=>r.json()).then(d=>{
    $('#nx-edit-name').textContent=name;
    $('#nx-editor-text').value=d.config||'';
    $('#nginx-editor').style.display='block';
    $('#nginx-editor').scrollIntoView({behavior:'smooth'});
  });
}

function nginxSaveConfig(){
  const name=$('#nx-edit-name').textContent;
  const config=$('#nx-editor-text').value;
  fetch('/api/manage/nginx/edit-site',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name,config:config})}).then(r=>r.json()).then(d=>{
    if(d.success){$('#nginx-editor').style.display='none';setTimeout(nginxRefresh,500);}
    else alert('Config test failed: '+(d.output||'unknown error'));
  });
}


</script>
</body></html>'''


@app.route('/api/shutdown', methods=['POST'])
def api_shutdown():
    """Gracefully shut down AEGIS."""
    _cleanup_subprocesses()
    func = request.environ.get('werkzeug.server.shutdown')
    if func:
        func()
        return jsonify({"status": "shutting down"})
    # Werkzeug >= 2.0 doesn't expose shutdown, use os._exit
    import os, signal
    threading.Timer(0.5, lambda: os.kill(os.getpid(), signal.SIGTERM)).start()
    return jsonify({"status": "shutting down"})


# ═══════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(description="AEGIS Security Dashboard v5")
    parser.add_argument("-p", "--port", type=int, default=5000, help="Web UI port")
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()

    # Clean up orphaned SSH processes from previous AEGIS runs
    _cleanup_orphaned_ssh()

    print(f"\n  ◆ AEGIS Security Dashboard v5.7 (2026-02-25)")
    print(f"  Dashboard: http://localhost:{args.port}")
    print(f"  {'─'*40}")
    print(f"  Login in the browser to connect.")
    fernet = _get_fernet()
    print(f"  Credential storage: {'✓ Fernet encrypted' if fernet else '✗ pip install cryptography for encrypted passwords'}")
    print(f"  Press Ctrl+C to stop the server.")
    print()

    import logging
    logging.getLogger('werkzeug').setLevel(logging.WARNING)

    if not args.no_browser:
        threading.Timer(1.5, lambda: webbrowser.open(f"http://localhost:{args.port}")).start()

    app.run(host="0.0.0.0", port=args.port, debug=False, use_reloader=False)


def _cleanup_orphaned_ssh():
    """Kill leftover SSH processes and control sockets from previous AEGIS runs."""
    import tempfile, shutil, glob
    # Clean up stale aegis_ssh_* temp directories
    tmp = tempfile.gettempdir()
    for d in glob.glob(os.path.join(tmp, 'aegis_ssh_*')):
        try:
            shutil.rmtree(d, ignore_errors=True)
        except: pass
    # On Windows: find and kill orphaned ssh.exe processes that match our pattern
    if IS_WIN:
        try:
            out = subprocess.check_output(
                ['wmic', 'process', 'where', "name='ssh.exe'", 'get', 'processid,commandline', '/format:csv'],
                text=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
            for line in out.split('\n'):
                if 'aegis_ssh_' in line.lower() or 'ControlMaster' in line or 'ControlPersist' in line:
                    parts = line.strip().rstrip(',').split(',')
                    if parts:
                        pid = parts[-1].strip()
                        if pid.isdigit():
                            try:
                                os.kill(int(pid), signal.SIGTERM)
                                print(f"  [cleanup] Killed orphaned SSH process PID {pid}")
                            except: pass
        except: pass
    else:
        # Unix: kill ssh processes with aegis control sockets
        try:
            out = subprocess.check_output(['pgrep', '-af', 'aegis_ssh_'], text=True, timeout=30)
            for line in out.strip().split('\n'):
                if line.strip():
                    pid = line.split()[0]
                    try:
                        os.kill(int(pid), signal.SIGTERM)
                        print(f"  [cleanup] Killed orphaned SSH process PID {pid}")
                    except: pass
        except: pass

if __name__ == "__main__":
    main()
