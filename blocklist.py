"""
blocklist.py
------------
Answers the question: "is this domain/IP usable, or has the admin blocked it?"
Also handles whole-device blocking (cutting a device off from the internet
entirely, not just specific domains).
"""

import subprocess
from models import BlockedEntry
import config


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


def enforce_block(value: str, entry_type: str):
    """Push the rule down to dnsmasq or iptables so it's actually denied."""
    if config.BLOCK_METHOD == "dns" and entry_type == "domain":
        _append_dnsmasq_rule(value)
    elif config.BLOCK_METHOD == "iptables" and entry_type == "ip":
        _add_iptables_drop(value)


def unenforce_block(value: str, entry_type: str):
    if config.BLOCK_METHOD == "dns" and entry_type == "domain":
        _remove_dnsmasq_rule(value)
    elif config.BLOCK_METHOD == "iptables" and entry_type == "ip":
        _remove_iptables_drop(value)


# ---- dnsmasq (DNS-layer blocking) ----
def _append_dnsmasq_rule(domain: str):
    """
    dnsmasq's address= directive returns 0.0.0.0 for a domain, which the
    client treats as unreachable — this is what actually 'denies' the request.
    Requires: sudo systemctl restart dnsmasq  after writing.
    """
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
    try:
        subprocess.run(["sudo", "systemctl", "restart", "dnsmasq"], check=False)
    except FileNotFoundError:
        pass  # not on a Pi / dnsmasq not installed — fine during dev


# ---- iptables (IP-layer blocking) ----
def _add_iptables_drop(ip: str):
    subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-d", ip, "-j", "DROP"], check=False)


def _remove_iptables_drop(ip: str):
    subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP"], check=False)


# ---- Whole-device blocking ----
# Different from the domain/IP blocklist above: this drops ALL traffic
# *from* a given device's IP (source), not just requests *to* a specific
# destination. Effectively disconnects that device from the internet.
def block_device(ip: str):
    subprocess.run(["sudo", "iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"], check=False)


def unblock_device(ip: str):
    subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"], check=False)
