"""
blocklist.py
------------
Answers the question: "is this domain/IP usable, or has the admin blocked it?"
Handles:
1. Domain and subdomain blocking with automatic service & CDN expansion:
   Blocking youtube.com blocks *.youtube.com, *.googlevideo.com, *.ytimg.com, etc.
   Blocking instagram.com blocks *.instagram.com, *.cdninstagram.com, *.ig.me, etc.
2. Immediate firewall enforcement on resolved IPs:
   Pre-resolves domain/CDN IPs and adds firewall DROP rules immediately so
   clients cannot continue streaming using locally cached DNS.
3. Layer 2 Wi-Fi Rejection & Deauthentication:
   When a device is blocked on Raspberry Pi, hostapd_cli deny_acl ADD_MAC and
   iw station del permanently kick and reject the device from connecting to Wi-Fi.
4. Layer 3 packet dropping (iptables on Linux/Pi, netsh advfirewall on Windows).
5. Active connection state flushing (conntrack on Linux, ARP cache flush on Windows).
"""

import os
import subprocess
import platform
import socket
import re
from models import BlockedEntry
import validators
import config

IS_WINDOWS = platform.system() == "Windows"
DNSMASQ_DENY_FILE = "/etc/dnsmasq.d/guardspot_deny.conf"


# ==============================================================================
# Domain & App CDN Expansions
# Modern apps stream media from separate CDNs and API hostnames.
# Blocking only the root domain leaves video/feed streaming functional.
# This mapping ensures blocking an app blocks ALL associated streaming endpoints.
# ==============================================================================

DOMAIN_APP_EXPANSIONS = {
    "youtube.com": [
        "googlevideo.com",
        "ytimg.com",
        "youtu.be",
        "youtube-nocookie.com",
        "youtubei.googleapis.com",
        "yt3.ggpht.com",
    ],
    "instagram.com": [
        "cdninstagram.com",
        "ig.me",
        "threads.net",
        "instagram.c10r.facebook.com",
        "graph.instagram.com",
    ],
    "tiktok.com": [
        "tiktokcdn.com",
        "tiktokv.com",
        "byteoversea.com",
        "ibytedtos.com",
        "musical.ly",
        "ttwstatic.com",
        "tiktokcdn-us.com",
    ],
    "facebook.com": [
        "fbcdn.net",
        "facebook.net",
        "fb.com",
        "fb.me",
        "fbsbx.com",
        "messenger.com",
    ],
    "whatsapp.com": [
        "whatsapp.net",
        "wa.me",
    ],
    "netflix.com": [
        "nflxvideo.net",
        "nflximg.net",
        "nflxext.com",
        "nflxso.net",
        "netflix.net",
    ],
    "snapchat.com": [
        "sc-cdn.net",
        "snap-dev.net",
        "snapads.com",
    ],
    "twitter.com": [
        "twimg.com",
        "t.co",
        "x.com",
    ],
    "x.com": [
        "twimg.com",
        "t.co",
        "twitter.com",
    ],
    "spotify.com": [
        "scdn.co",
        "spotifycdn.com",
        "spoti.fi",
    ],
    "reddit.com": [
        "redd.it",
        "redditmedia.com",
        "redditstatic.com",
    ],
    "roblox.com": [
        "rbxcdn.com",
        "robloxlabs.com",
    ],
    "twitch.tv": [
        "ttvnw.net",
        "jtvnw.net",
    ],
    "discord.com": [
        "discordapp.com",
        "discord.gg",
        "discordapp.net",
    ],
    "pinterest.com": [
        "pinimg.com",
    ],
}

# Inverted index: maps any CDN or alias domain back to its root service
EXPANSION_TO_ROOT = {}
for root, alts in DOMAIN_APP_EXPANSIONS.items():
    EXPANSION_TO_ROOT[root] = root
    for alt in alts:
        EXPANSION_TO_ROOT[alt] = root


def get_root_service(domain: str) -> str:
    """Return the parent service root domain if this is a known CDN or alternate domain."""
    return EXPANSION_TO_ROOT.get(domain)


def get_expanded_domains(domain: str) -> list:
    """Return all related domains and CDNs for a given service."""
    norm = validators.normalize_domain(domain)
    if norm in DOMAIN_APP_EXPANSIONS:
        return [norm] + DOMAIN_APP_EXPANSIONS[norm]
    root = EXPANSION_TO_ROOT.get(norm)
    if root and root in DOMAIN_APP_EXPANSIONS:
        return [root] + DOMAIN_APP_EXPANSIONS[root]
    return [norm]


def lookup_mac(ip: str) -> str:
    """Find MAC address for an IP from the system ARP table."""
    try:
        if config.IS_PI or platform.system() != "Linux":
            pass
        if platform.system() == "Linux":
            with open("/proc/net/arp", "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip:
                        mac = parts[3]
                        if mac != "00:00:00:00:00:00":
                            return mac.upper()
        else:
            out = subprocess.check_output(f"arp -a {ip}", shell=True, text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                if ip in line:
                    match = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", line)
                    if match:
                        return match.group(0).replace("-", ":").upper()
    except Exception:
        pass
    return None


def is_blocked(domain: str, resolved_ip: str = None) -> bool:
    """
    Check if a domain, any of its parent domains, its service family (CDNs),
    or its resolved IP is blocked.
    """
    if not domain and not resolved_ip:
        return False

    if domain:
        clean_domain = validators.normalize_domain(domain)
        parts = clean_domain.split(".")

        # Generate candidates: e.g. for "v16.api.tiktok.com" ->
        # ["v16.api.tiktok.com", "api.tiktok.com", "tiktok.com"]
        candidates = []
        for i in range(len(parts) - 1):
            candidates.append(".".join(parts[i:]))

        if candidates:
            # 1. Direct candidate matching
            match = BlockedEntry.query.filter(
                BlockedEntry.entry_type == "domain",
                BlockedEntry.value.in_(candidates)
            ).first()
            if match:
                return True

            # 2. Service family expansion check (e.g. googlevideo.com -> youtube.com)
            root_candidates = []
            for c in candidates:
                root = get_root_service(c)
                if root and root not in root_candidates:
                    root_candidates.append(root)

            if root_candidates:
                match_root = BlockedEntry.query.filter(
                    BlockedEntry.entry_type == "domain",
                    BlockedEntry.value.in_(root_candidates)
                ).first()
                if match_root:
                    return True

    if resolved_ip:
        match_ip = BlockedEntry.query.filter_by(value=resolved_ip, entry_type="ip").first()
        if match_ip:
            return True

    return False


def add_block(value: str, entry_type: str, reason: str = "", db=None):
    """Admin adds a domain/IP to the blocklist AND pushes it to the OS-level enforcer."""
    if entry_type == "domain":
        value = validators.normalize_domain(value)
    else:
        value = value.strip()

    existing = BlockedEntry.query.filter_by(value=value, entry_type=entry_type).first()
    if existing:
        return existing

    entry = BlockedEntry(value=value, entry_type=entry_type, reason=reason)
    db.session.add(entry)
    db.session.commit()
    enforce_block(value, entry_type)
    return entry


def remove_block(entry_id: int, db=None):
    """Admin removes a domain/IP from the blocklist and lifts the OS enforcement."""
    entry = BlockedEntry.query.get(entry_id)
    if entry:
        unenforce_block(entry.value, entry.entry_type)
        db.session.delete(entry)
        db.session.commit()


def _run_privileged(cmd: list):
    """Run a command that needs root/admin. Never crashes Flask."""
    try:
        # If running as root on Linux, strip 'sudo' so it executes directly without TTY checks
        if platform.system() == "Linux" and os.geteuid() == 0 and cmd and cmd[0] == "sudo":
            cmd = cmd[1:]
        result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=10)
        if result.returncode != 0 and result.stderr:
            print(f"[blocklist] command notice ({result.returncode}): {' '.join(cmd)}\n{result.stderr.strip()}")
        return result
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        print(f"[blocklist] command timed out: {' '.join(cmd)}")
    except Exception as e:
        print(f"[blocklist] execution error: {e}")
    return None


# ==============================================================================
# Windows Firewall Enforcement (Laptop Hotspot Mode)
# ==============================================================================

def _windows_add_ip_rule(rule_name: str, ip: str):
    """
    Creates both Inbound and Outbound block rules on Windows for an IP.
    Blocks all protocols (TCP, UDP/QUIC, ICMP) and all firewall profiles.
    """
    _run_privileged([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}_In", "dir=in", "action=block",
        f"remoteip={ip}", "protocol=any", "profile=any"
    ])
    _run_privileged([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}_Out", "dir=out", "action=block",
        f"remoteip={ip}", "protocol=any", "profile=any"
    ])


def _windows_remove_rules(rule_name: str):
    """Removes firewall rules matching a name or prefix."""
    _run_privileged(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}_In"])
    _run_privileged(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}_Out"])
    _run_privileged(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"])

    if "*" in rule_name:
        ps_cmd = [
            "powershell", "-NoProfile", "-Command",
            f'Get-NetFirewallRule -DisplayName "{rule_name}" -ErrorAction SilentlyContinue | Remove-NetFirewallRule'
        ]
        _run_privileged(ps_cmd)


def resolve_domain_ips(domain: str) -> list:
    """Resolve a domain and its common prefixes to published IPv4/IPv6 addresses."""
    ips = []
    targets = [domain]
    if not domain.startswith("www."):
        targets.append(f"www.{domain}")
    if not domain.startswith("m."):
        targets.append(f"m.{domain}")

    for t in targets:
        try:
            addr_info = socket.getaddrinfo(t, None)
            for item in addr_info:
                ip = item[4][0]
                if ip and ip not in ips and ip != "0.0.0.0" and ip != "::":
                    ips.append(ip)
        except Exception:
            pass
    return ips


def enforce_domain_ip(domain: str, ip: str):
    """Called when an IP for a blocked domain is detected in live traffic."""
    safe_domain = re.sub(r'[^a-zA-Z0-9.-]', '_', domain)
    if IS_WINDOWS:
        _windows_add_ip_rule(f"GuardSpot_DomainIP_{safe_domain}_{ip}", ip)
    else:
        _add_iptables_drop(ip)


# ==============================================================================
# Linux / Raspberry Pi Enforcement (dnsmasq + hostapd + iptables)
# ==============================================================================

def _append_dnsmasq_rule(domain: str):
    """Appends address=/domain/0.0.0.0 and :: to dnsmasq config to sinkhole domain and all subdomains."""
    lines = [
        f"address=/{domain}/0.0.0.0\n",
        f"address=/{domain}/::\n",
    ]
    try:
        os.makedirs(os.path.dirname(config.DNSMASQ_BLOCKLIST_FILE), exist_ok=True)
        existing = ""
        if os.path.exists(config.DNSMASQ_BLOCKLIST_FILE):
            with open(config.DNSMASQ_BLOCKLIST_FILE, "r") as f:
                existing = f.read()
        with open(config.DNSMASQ_BLOCKLIST_FILE, "a") as f:
            for l in lines:
                if l not in existing:
                    f.write(l)
        _restart_dnsmasq()
    except Exception as e:
        print(f"[blocklist] Failed to write dnsmasq rule: {e}")


def _remove_dnsmasq_rule(domain: str):
    """Removes domain sinkhole rules from dnsmasq config."""
    try:
        if not os.path.exists(config.DNSMASQ_BLOCKLIST_FILE):
            return
        with open(config.DNSMASQ_BLOCKLIST_FILE, "r") as f:
            lines = f.readlines()
        with open(config.DNSMASQ_BLOCKLIST_FILE, "w") as f:
            for line in lines:
                if f"/{domain}/" not in line:
                    f.write(line)
        _restart_dnsmasq()
    except Exception as e:
        print(f"[blocklist] Failed to remove dnsmasq rule: {e}")


def _restart_dnsmasq():
    """Reloads dnsmasq to apply blocklist changes without dropping leases."""
    res = _run_privileged(["sudo", "killall", "-HUP", "dnsmasq"])
    if not res or res.returncode != 0:
        _run_privileged(["sudo", "systemctl", "reload", "dnsmasq"])


def _hostapd_deny_add(mac: str):
    """
    Blocks a client at Layer 2 Wi-Fi on Raspberry Pi.
    1. hostapd_cli deny_acl ADD_MAC: immediately rejects 802.11 association.
    2. hostapd_cli deauthenticate: forces immediate Wi-Fi disconnect frame.
    3. iw dev <iface> station del: evicts station from wireless kernel driver.
    4. /etc/hostapd/hostapd.deny: persists block across hostapd restarts.
    """
    if not mac:
        return
    norm_mac = mac.upper()

    # Runtime hostapd ACL + deauthentication
    _run_privileged(["sudo", "hostapd_cli", "deny_acl", "ADD_MAC", norm_mac])
    _run_privileged(["sudo", "hostapd_cli", "deauthenticate", norm_mac])
    _run_privileged(["sudo", "hostapd_cli", "disassociate", norm_mac])

    # Direct Linux kernel station eviction
    _run_privileged(["sudo", "iw", "dev", config.CAPTURE_INTERFACE, "station", "del", norm_mac])

    # Persistent deny files
    for path in ["/etc/hostapd/hostapd.deny", "/etc/hostapd.deny"]:
        try:
            dirname = os.path.dirname(path)
            if os.path.exists(dirname):
                existing_lines = []
                if os.path.exists(path):
                    with open(path, "r") as f:
                        existing_lines = [l.strip().upper() for l in f]
                if norm_mac not in existing_lines:
                    with open(path, "a") as f:
                        f.write(f"{norm_mac}\n")
        except Exception as e:
            print(f"[blocklist] hostapd deny write error ({path}): {e}")


def _hostapd_deny_remove(mac: str):
    """Lifts Layer 2 Wi-Fi block in hostapd."""
    if not mac:
        return
    norm_mac = mac.upper()
    _run_privileged(["sudo", "hostapd_cli", "deny_acl", "DEL_MAC", norm_mac])

    for path in ["/etc/hostapd/hostapd.deny", "/etc/hostapd.deny"]:
        try:
            if os.path.exists(path):
                with open(path, "r") as f:
                    lines = f.readlines()
                with open(path, "w") as f:
                    for line in lines:
                        if norm_mac != line.strip().upper():
                            f.write(line)
        except Exception as e:
            print(f"[blocklist] hostapd deny remove error ({path}): {e}")


def _dnsmasq_deny_add(mac: str):
    """Instructs dnsmasq to ignore DHCP requests from this MAC."""
    if not mac:
        return
    norm_mac = mac.upper()
    rule = f"dhcp-host={norm_mac},ignore\n"
    try:
        os.makedirs(os.path.dirname(DNSMASQ_DENY_FILE), exist_ok=True)
        existing = ""
        if os.path.exists(DNSMASQ_DENY_FILE):
            with open(DNSMASQ_DENY_FILE, "r") as f:
                existing = f.read()
        if rule not in existing:
            with open(DNSMASQ_DENY_FILE, "a") as f:
                f.write(rule)
            _restart_dnsmasq()
    except Exception as e:
        print(f"[blocklist] dnsmasq deny write error: {e}")


def _dnsmasq_deny_remove(mac: str):
    """Restores DHCP service for this MAC."""
    if not mac or not os.path.exists(DNSMASQ_DENY_FILE):
        return
    norm_mac = mac.upper()
    try:
        with open(DNSMASQ_DENY_FILE, "r") as f:
            lines = f.readlines()
        with open(DNSMASQ_DENY_FILE, "w") as f:
            for line in lines:
                if norm_mac not in line.upper():
                    f.write(line)
        _restart_dnsmasq()
    except Exception as e:
        print(f"[blocklist] dnsmasq deny remove error: {e}")


def _add_iptables_drop(ip: str):
    """Insert DROP rule at position 1 to precede RELATED,ESTABLISHED."""
    _run_privileged(["sudo", "iptables", "-I", "FORWARD", "1", "-d", ip, "-j", "DROP"])
    _run_privileged(["sudo", "iptables", "-I", "FORWARD", "1", "-s", ip, "-j", "DROP"])
    _run_privileged(["sudo", "iptables", "-I", "OUTPUT", "1", "-d", ip, "-j", "DROP"])
    # Terminate active TCP/UDP sessions immediately so video streams halt
    _run_privileged(["sudo", "conntrack", "-D", "-d", ip])


def _remove_iptables_drop(ip: str):
    _run_privileged(["sudo", "iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP"])
    _run_privileged(["sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"])
    _run_privileged(["sudo", "iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"])


# ==============================================================================
# Public Enforcement Functions
# ==============================================================================

def enforce_block(value: str, entry_type: str):
    """Push a block rule down to the OS and firewalls."""
    if entry_type == "ip":
        if IS_WINDOWS:
            _windows_add_ip_rule(f"GuardSpot_Block_IP_{value}", value)
        else:
            _add_iptables_drop(value)
        return

    # entry_type == "domain"
    # Expand to all associated CDNs and streaming endpoints
    expanded_domains = get_expanded_domains(value)

    for dom in expanded_domains:
        safe_domain = re.sub(r'[^a-zA-Z0-9.-]', '_', dom)
        ips = resolve_domain_ips(dom)

        if IS_WINDOWS:
            for ip in ips:
                _windows_add_ip_rule(f"GuardSpot_Domain_{safe_domain}_{ip}", ip)
        else:
            _append_dnsmasq_rule(dom)
            for ip in ips:
                _add_iptables_drop(ip)


def unenforce_block(value: str, entry_type: str):
    """Remove a block rule from the OS and firewalls."""
    if entry_type == "ip":
        if IS_WINDOWS:
            _windows_remove_rules(f"GuardSpot_Block_IP_{value}")
        else:
            _remove_iptables_drop(value)
        return

    # entry_type == "domain"
    expanded_domains = get_expanded_domains(value)
    for dom in expanded_domains:
        safe_dom = re.sub(r'[^a-zA-Z0-9.-]', '_', dom)
        if IS_WINDOWS:
            _windows_remove_rules(f"GuardSpot_Domain_{safe_dom}_*")
            _windows_remove_rules(f"GuardSpot_DomainIP_{safe_dom}_*")
        else:
            _remove_dnsmasq_rule(dom)
            ips = resolve_domain_ips(dom)
            for ip in ips:
                _remove_iptables_drop(ip)


# ==============================================================================
# Whole-Device Blocking / Unblocking
# ==============================================================================

def block_device(ip: str, mac: str = None):
    """
    Completely cuts a device off from the Wi-Fi network, local LAN, and internet.
    1. Layer 2 Wi-Fi Rejection: Adds MAC to hostapd deny ACL, deauthenticates, and evicts station.
       The device cannot re-associate or connect to the Wi-Fi.
    2. DHCP Rejection: Tells dnsmasq to ignore DHCP requests from this MAC.
    3. Layer 3 Firewall Dropping: Drops all incoming and outgoing packets (TCP, UDP, ICMP).
    4. Active Connection Killing: Kills conntrack sessions on Linux, flushes ARP on Windows.
    """
    if not mac:
        mac = lookup_mac(ip)

    print(f"[blocklist] Blocking entire device: IP={ip}, MAC={mac}")

    if IS_WINDOWS:
        # Windows Firewall: Block ALL protocols, ALL ports, In and Out
        _windows_add_ip_rule(f"GuardSpot_BlockDevice_{ip}", ip)
        # Flush ARP table
        _run_privileged(["netsh", "interface", "ip", "delete", "arpcache"])
        return

    # Linux / Raspberry Pi (Wi-Fi Access Point or Ethernet)
    # 1. Kill active connection states immediately
    _run_privileged(["sudo", "conntrack", "-D", "-s", ip])
    _run_privileged(["sudo", "conntrack", "-D", "-d", ip])

    # 2. Firewall IP packet dropping at top of chains
    _run_privileged(["sudo", "iptables", "-I", "FORWARD", "1", "-s", ip, "-j", "DROP"])
    _run_privileged(["sudo", "iptables", "-I", "FORWARD", "1", "-d", ip, "-j", "DROP"])
    _run_privileged(["sudo", "iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"])
    _run_privileged(["sudo", "iptables", "-I", "OUTPUT", "1", "-d", ip, "-j", "DROP"])

    if mac:
        # 3. Firewall MAC packet dropping
        _run_privileged(["sudo", "iptables", "-I", "FORWARD", "1", "-m", "mac", "--mac-source", mac, "-j", "DROP"])
        _run_privileged(["sudo", "iptables", "-I", "INPUT", "1", "-m", "mac", "--mac-source", mac, "-j", "DROP"])

        # 4. Layer 2 Wi-Fi Rejection: kick client from wlan0 driver and add to hostapd deny
        _run_privileged(["sudo", "iw", "dev", "wlan0", "station", "del", mac.lower()])
        _run_privileged(["sudo", "iw", "dev", "wlan0", "station", "del", mac.upper()])
        _hostapd_deny_add(mac)

        # 5. DHCP Rejection: refuse to assign IP address to this MAC
        _dnsmasq_deny_add(mac)


def unblock_device(ip: str, mac: str = None):
    """Restores network and Wi-Fi access for a previously blocked device."""
    if not mac:
        mac = lookup_mac(ip)

    print(f"[blocklist] Unblocking device: IP={ip}, MAC={mac}")

    if IS_WINDOWS:
        _windows_remove_rules(f"GuardSpot_BlockDevice_{ip}")
        return

    # Linux / Raspberry Pi
    _run_privileged(["sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"])
    _run_privileged(["sudo", "iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP"])
    _run_privileged(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
    _run_privileged(["sudo", "iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"])

    if mac:
        _run_privileged(["sudo", "iptables", "-D", "FORWARD", "-m", "mac", "--mac-source", mac, "-j", "DROP"])
        _run_privileged(["sudo", "iptables", "-D", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP"])
        # Remove from hostapd deny list
        _hostapd_deny_remove(mac)
        # Remove from dnsmasq DHCP ignore list
        _dnsmasq_deny_remove(mac)
