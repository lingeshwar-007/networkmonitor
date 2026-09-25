"""
blocklist.py
------------
Answers the question: "is this domain/IP usable, or has the admin blocked it?"
Also handles whole-device blocking (cutting a device off from the internet
entirely, not just specific domains).
"""

import subprocess
import platform
from models import BlockedEntry
import config

IS_WINDOWS = platform.system() == "Windows"


def is_blocked(domain: str, resolved_ip: str = None) -> bool:
    """Check the DB blocklist for a domain or its resolved IP."""
    domain = domain.rstrip(".").lower()

    match = BlockedEntry.query.filter_by(value=domain, entry_type="domain").first()
    if match:
        return True

    if resolved_ip:
        match_ip = BlockedEntry.query.filter_by(value=resolved_ip, entry_type="ip").first()
        if match_ip:
            return True

    return False


def add_block(value: str, entry_type: str, reason: str = "", db=None):
    """Admin adds a domain/IP to the blocklist AND pushes it to the OS-level enforcer."""
    entry = BlockedEntry(value=value.lower(), entry_type=entry_type, reason=reason)
    db.session.add(entry)
    db.session.commit()
    enforce_block(value, entry_type)
    return entry


def remove_block(entry_id: int, db=None):
    entry = BlockedEntry.query.get(entry_id)
    if entry:
        unenforce_block(entry.value, entry.entry_type)
        db.session.delete(entry)
        db.session.commit()


def _run_privileged(cmd: list):
    """Run a command that needs root/admin (iptables/systemctl/powershell via sudo).
    Never raises -- logs and returns instead of crashing the Flask request
    that called it if sudo/iptables/systemctl aren't available."""
    try:
        result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            print(f"[blocklist] command failed ({result.returncode}): {' '.join(cmd)}\n{result.stderr}")
        return result
    except FileNotFoundError:
        print(f"[blocklist] '{cmd[0]}' not found -- not on the Pi, or not installed. Skipping enforcement.")
    except subprocess.TimeoutExpired:
        print(f"[blocklist] command timed out (sudo waiting for a password with no TTY?): {' '.join(cmd)}")
    return None


# ---- dnsmasq (DNS-layer blocking, Linux/Pi only) ----
def _append_dnsmasq_rule(domain: str):
    line = f"address=/{domain}/0.0.0.0\n"
    with open(config.DNSMASQ_BLOCKLIST_FILE, "a") as f:
        f.write(line)
    _restart_dnsmasq()


def _remove_dnsmasq_rule(domain: str):
    try:
        with open(config.DNSMASQ_BLOCKLIST_FILE, "r") as f:
            lines = f.readlines()
        with open(config.DNSMASQ_BLOCKLIST_FILE, "w") as f:
            for line in lines:
                if f"/{domain}/" not in line:
                    f.write(line)
        _restart_dnsmasq()
    except FileNotFoundError:
        pass


def _restart_dnsmasq():
    _run_privileged(["sudo", "systemctl", "restart", "dnsmasq"])


def _add_iptables_drop(ip: str):
    _run_privileged(["sudo", "iptables", "-A", "FORWARD", "-d", ip, "-j", "DROP"])


def _remove_iptables_drop(ip: str):
    _run_privileged(["sudo", "iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP"])


# ---- Windows Firewall (blocking, laptop-hotspot mode) ----
def _windows_add_rule(rule_name: str, remote_ip: str):
    cmd = [
        "powershell", "-NoProfile", "-Command",
        f'if (-not (Get-NetFirewallRule -DisplayName "{rule_name}" -ErrorAction SilentlyContinue)) '
        f'{{ New-NetFirewallRule -DisplayName "{rule_name}" -Direction Outbound -RemoteAddress {remote_ip} -Action Block | Out-Null }}'
    ]
    _run_privileged(cmd)


def _windows_remove_rules(name_pattern: str):
    cmd = [
        "powershell", "-NoProfile", "-Command",
        f'Get-NetFirewallRule -DisplayName "{name_pattern}" -ErrorAction SilentlyContinue | Remove-NetFirewallRule'
    ]
    _run_privileged(cmd)


def enforce_domain_ip(domain: str, ip: str):
    """Called by sniffer.py when it sees a DNS *response* resolving a
    currently-blocked domain to `ip`. Windows only -- on the Pi, dnsmasq
    already prevents resolution before this would ever be needed."""
    if IS_WINDOWS:
        _windows_add_rule(f"GuardSpot_Block_{domain}_{ip}", ip)


def enforce_block(value: str, entry_type: str):
    """Push the rule down to the OS so it's actually denied."""
    if IS_WINDOWS:
        if entry_type == "ip":
            _windows_add_rule(f"GuardSpot_Block_IP_{value}", value)
        # domain: nothing to enforce yet -- sniffer.py's response handler
        # firewalls each resolved IP as it's seen.
        return
    if entry_type == "domain":
        _append_dnsmasq_rule(value)
    elif entry_type == "ip":
        _add_iptables_drop(value)


def unenforce_block(value: str, entry_type: str):
    if IS_WINDOWS:
        if entry_type == "domain":
            _windows_remove_rules(f"GuardSpot_Block_{value}_*")
        elif entry_type == "ip":
            _windows_remove_rules(f"GuardSpot_Block_IP_{value}")
        return
    if entry_type == "domain":
        _remove_dnsmasq_rule(value)
    elif entry_type == "ip":
        _remove_iptables_drop(value)


def block_device(ip: str):
    if IS_WINDOWS:
        _windows_add_rule(f"GuardSpot_BlockDevice_{ip}", ip)
        return
    _run_privileged(["sudo", "iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"])


def unblock_device(ip: str):
    if IS_WINDOWS:
        _windows_remove_rules(f"GuardSpot_BlockDevice_{ip}")
        return
    _run_privileged(["sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"])
