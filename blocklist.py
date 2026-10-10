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
        "instagram.com",
        "i.instagram.com",
        "cdninstagram.com",
        "ig.me",
        "threads.net",
        "instagram.c10r.facebook.com",
        "graph.instagram.com",
        "edge-chat.instagram.com",
        "b.instagram.com",
        "api.instagram.com",
        "gateway.instagram.com",
        "fbcdn.net",
        "facebook.com",
        "facebook.net",
        "fbsbx.com",
        "meta.com",
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
        "instagram.com",
        "threads.net",
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

# ==============================================================================
# Autonomous System / Hard CIDR IP Ranges
# For major apps (Meta/Instagram, TikTok, Netflix), IP routing can bypass DNS.
# Dropping their dedicated CIDR IP blocks at Layer 3/4 completely terminates traffic.
# ==============================================================================

SERVICE_CIDR_BLOCKS = {
    "instagram.com": [
        "157.240.0.0/16",
        "57.144.0.0/14",
        "31.13.64.0/18",
        "31.13.24.0/21",
        "31.13.78.0/24",
        "31.13.79.0/24",
        "31.13.80.0/24",
        "31.13.96.0/19",
        "179.60.192.0/22",
        "185.60.216.0/22",
        "204.15.20.0/22",
        "69.63.176.0/20",
        "69.171.224.0/19",
        "66.220.144.0/20",
        "129.134.0.0/16",
        "173.252.64.0/18",
        "2a03:2880::/32",
        "2620:0:1c00::/40",
        "2a03:2884::/32",
        "2a03:2887::/32",
    ],
    "facebook.com": [
        "157.240.0.0/16",
        "57.144.0.0/14",
        "31.13.64.0/18",
        "31.13.24.0/21",
        "31.13.78.0/24",
        "31.13.79.0/24",
        "31.13.80.0/24",
        "31.13.96.0/19",
        "179.60.192.0/22",
        "185.60.216.0/22",
        "204.15.20.0/22",
        "69.63.176.0/20",
        "69.171.224.0/19",
        "66.220.144.0/20",
        "129.134.0.0/16",
        "173.252.64.0/18",
        "2a03:2880::/32",
        "2620:0:1c00::/40",
        "2a03:2884::/32",
        "2a03:2887::/32",
    ],
    "whatsapp.com": [
        "157.240.0.0/16",
        "57.144.0.0/14",
        "31.13.64.0/18",
        "185.60.216.0/22",
        "2a03:2880::/32",
    ],
    "tiktok.com": [
        "161.117.0.0/16",
        "152.199.19.0/24",
        "152.199.20.0/24",
        "143.204.0.0/16",
    ],
    "netflix.com": [
        "198.38.96.0/19",
        "198.45.48.0/20",
        "23.246.0.0/18",
        "37.77.184.0/21",
        "45.57.0.0/17",
        "64.120.128.0/17",
        "66.197.128.0/17",
        "69.53.224.0/19",
        "108.175.32.0/20",
        "185.2.220.0/22",
        "185.9.188.0/22",
        "192.173.64.0/18",
        "2a00:86c0::/32",
        "2a03:5640::/32",
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


def get_service_cidrs(domain: str) -> list:
    """Return published Autonomous System IP CIDR blocks for domain or its root service."""
    norm = validators.normalize_domain(domain)
    if norm in SERVICE_CIDR_BLOCKS:
        return SERVICE_CIDR_BLOCKS[norm]
    parts = norm.split(".")
    if len(parts) >= 2:
        base = ".".join(parts[-2:])
        if base in SERVICE_CIDR_BLOCKS:
            return SERVICE_CIDR_BLOCKS[base]
    root = EXPANSION_TO_ROOT.get(norm)
    if root and root in SERVICE_CIDR_BLOCKS:
        return SERVICE_CIDR_BLOCKS[root]
    return []


def get_expanded_domains(domain: str) -> list:
    """Return all related domains and CDNs for a given service."""
    norm = validators.normalize_domain(domain)
    
    # Check exact match
    if norm in DOMAIN_APP_EXPANSIONS:
        return list(set([norm] + DOMAIN_APP_EXPANSIONS[norm]))
    
    # Check parent/base domain (e.g. i.instagram.com -> instagram.com)
    parts = norm.split(".")
    if len(parts) >= 2:
        base = ".".join(parts[-2:])
        if base in DOMAIN_APP_EXPANSIONS:
            return list(set([base, norm] + DOMAIN_APP_EXPANSIONS[base]))

    root = EXPANSION_TO_ROOT.get(norm)
    if root and root in DOMAIN_APP_EXPANSIONS:
        return list(set([root, norm] + DOMAIN_APP_EXPANSIONS[root]))
    return [norm]


def lookup_mac(ip: str) -> str:
    """Find MAC address for an IP from ARP table, ip neighbor, or DHCP lease files."""
    if not ip:
        return None
    try:
        if platform.system() == "Linux":
            # 1. Check /proc/net/arp
            if os.path.exists("/proc/net/arp"):
                with open("/proc/net/arp", "r") as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 4 and parts[0] == ip:
                            mac = parts[3]
                            if mac != "00:00:00:00:00:00":
                                return mac.upper()

            # 2. Check ip neigh show
            try:
                out = subprocess.check_output(f"ip neigh show {ip}", shell=True, text=True, stderr=subprocess.DEVNULL)
                for line in out.splitlines():
                    match = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", line)
                    if match:
                        return match.group(0).replace("-", ":").upper()
            except Exception:
                pass

            # 3. Check DHCP lease files (NetworkManager & dnsmasq)
            import glob
            lease_files = [
                "/var/lib/NetworkManager/dnsmasq-wlan0.leases",
                "/var/lib/misc/dnsmasq.leases",
                "/run/NetworkManager/dnsmasq-wlan0.leases",
            ]
            for pattern in ["/var/lib/NetworkManager/dnsmasq-*.leases", "/run/NetworkManager/*.leases"]:
                lease_files.extend(glob.glob(pattern))

            for path in set(lease_files):
                if os.path.exists(path):
                    try:
                        with open(path, "r", errors="ignore") as f:
                            for line in f:
                                parts = line.split()
                                # Format: timestamp mac ip hostname client_id
                                if len(parts) >= 3 and parts[2] == ip:
                                    return parts[1].upper()
                    except Exception:
                        pass
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
    """Resolve a domain to published IPv4/IPv6 addresses with short timeout."""
    ips = []
    targets = [domain]
    # Only test www. if this is an apex domain (e.g. instagram.com, not api.instagram.com)
    if domain.count(".") == 1 and not domain.startswith("www."):
        targets.append(f"www.{domain}")

    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(0.5)
        for t in targets:
            try:
                addr_info = socket.getaddrinfo(t, None)
                for item in addr_info:
                    ip = item[4][0]
                    if ip and ip not in ips and ip not in ("0.0.0.0", "::"):
                        ips.append(ip)
            except Exception:
                pass
    finally:
        socket.setdefaulttimeout(old_timeout)
    return ips


def enforce_domain_ip(domain: str, ip: str):
    """Called when an IP for a blocked domain is detected in live traffic."""
    safe_domain = re.sub(r'[^a-zA-Z0-9.-]', '_', domain)
    if IS_WINDOWS:
        _windows_add_ip_rule(f"GuardSpot_DomainIP_{safe_domain}_{ip}", ip)
    else:
        _add_iptables_drop(ip)


# ==============================================================================
# Linux / Raspberry Pi Gateway Firewall (dnsmasq + NetworkManager + iptables)
# ==============================================================================

DNSMASQ_DIRS = [
    "/etc/dnsmasq.d",
    "/etc/NetworkManager/dnsmasq-shared.d",
]


def _append_dnsmasq_rule(domain: str):
    """Appends address=/domain/0.0.0.0 and :: to dnsmasq config to sinkhole domain and all subdomains."""
    lines = [
        f"address=/{domain}/0.0.0.0\n",
        f"address=/{domain}/::\n",
    ]
    for d in DNSMASQ_DIRS:
        try:
            if os.path.exists(d):
                filepath = os.path.join(d, "guardspot_blocklist.conf")
                existing = ""
                if os.path.exists(filepath):
                    with open(filepath, "r") as f:
                        existing = f.read()
                with open(filepath, "a") as f:
                    for l in lines:
                        if l not in existing:
                            f.write(l)
        except Exception as e:
            print(f"[blocklist] Failed to write dnsmasq rule ({d}): {e}")


def _remove_dnsmasq_rule(domain: str):
    """Removes domain sinkhole rules from all dnsmasq configs."""
    for d in DNSMASQ_DIRS:
        filepath = os.path.join(d, "guardspot_blocklist.conf")
        try:
            if os.path.exists(filepath):
                with open(filepath, "r") as f:
                    lines = f.readlines()
                with open(filepath, "w") as f:
                    for line in lines:
                        if f"/{domain}/" not in line:
                            f.write(line)
        except Exception as e:
            print(f"[blocklist] Failed to remove dnsmasq rule ({filepath}): {e}")


def _restart_dnsmasq():
    """Reloads dnsmasq and NetworkManager if active without dropping leases."""
    _run_privileged(["sudo", "killall", "-HUP", "dnsmasq"])
    # Check if dnsmasq systemd unit actually exists before attempting reload
    res = _run_privileged(["systemctl", "is-active", "--quiet", "dnsmasq"])
    if res and res.returncode == 0:
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

    # Direct Linux wireless kernel driver station eviction
    for iface in ("wlan0", "ap0", config.CAPTURE_INTERFACE):
        _run_privileged(["sudo", "iw", "dev", iface, "station", "del", norm_mac.lower()])
        _run_privileged(["sudo", "iw", "dev", iface, "station", "del", norm_mac.upper()])

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
    for d in DNSMASQ_DIRS:
        try:
            if os.path.exists(d):
                filepath = os.path.join(d, "guardspot_deny.conf")
                existing = ""
                if os.path.exists(filepath):
                    with open(filepath, "r") as f:
                        existing = f.read()
                if rule not in existing:
                    with open(filepath, "a") as f:
                        f.write(rule)
        except Exception as e:
            print(f"[blocklist] dnsmasq deny write error ({d}): {e}")
    _restart_dnsmasq()


def _dnsmasq_deny_remove(mac: str):
    """Restores DHCP service for this MAC."""
    if not mac:
        return
    norm_mac = mac.upper()
    for d in DNSMASQ_DIRS:
        filepath = os.path.join(d, "guardspot_deny.conf")
        try:
            if os.path.exists(filepath):
                with open(filepath, "r") as f:
                    lines = f.readlines()
                with open(filepath, "w") as f:
                    for line in lines:
                        if norm_mac not in line.upper():
                            f.write(line)
        except Exception as e:
            print(f"[blocklist] dnsmasq deny remove error ({filepath}): {e}")
    _restart_dnsmasq()


def _add_iptables_drop(ip_or_cidr: str):
    """Insert DROP rule at position 1 to precede RELATED,ESTABLISHED (supports IPv4, IPv6, and CIDRs)."""
    tool = "ip6tables" if ":" in ip_or_cidr else "iptables"
    check = _run_privileged(["sudo", tool, "-C", "FORWARD", "-d", ip_or_cidr, "-j", "DROP"])
    if not check or check.returncode != 0:
        _run_privileged(["sudo", tool, "-I", "FORWARD", "1", "-d", ip_or_cidr, "-j", "DROP"])
        _run_privileged(["sudo", tool, "-I", "FORWARD", "1", "-s", ip_or_cidr, "-j", "DROP"])
        _run_privileged(["sudo", tool, "-I", "OUTPUT", "1", "-d", ip_or_cidr, "-j", "DROP"])
    # Terminate active TCP/UDP sessions immediately so video/feed streams halt
    if "/" not in ip_or_cidr:
        _run_privileged(["sudo", "conntrack", "-D", "-d", ip_or_cidr])
        _run_privileged(["sudo", "conntrack", "-D", "-s", ip_or_cidr])
    else:
        _run_privileged(["sudo", "conntrack", "-F"])


def _remove_iptables_drop(ip_or_cidr: str):
    tool = "ip6tables" if ":" in ip_or_cidr else "iptables"
    _run_privileged(["sudo", tool, "-D", "FORWARD", "-d", ip_or_cidr, "-j", "DROP"])
    _run_privileged(["sudo", tool, "-D", "FORWARD", "-s", ip_or_cidr, "-j", "DROP"])
    _run_privileged(["sudo", tool, "-D", "OUTPUT", "-d", ip_or_cidr, "-j", "DROP"])


def is_port_53_listening() -> bool:
    """Check if a local DNS server is listening on port 53."""
    if IS_WINDOWS:
        return False
    try:
        out = subprocess.check_output("ss -lupn sport = :53", shell=True, text=True, stderr=subprocess.DEVNULL)
        if ":53" in out:
            return True
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("0.0.0.0", 53))
        s.close()
        return False
    except Exception:
        return True


def init_gateway_firewall():
    """
    Initializes Raspberry Pi / Linux gateway firewall foundations:
    1. Enables IP packet forwarding in sysctl.
    2. If a local DNS server is listening on port 53, redirects incoming DNS queries on hotspot interface to it.
       If not, cleans up stale redirects so DNS queries flow naturally to upstream.
    3. Blocks DNS-over-TLS (port 853) on IPv4 & IPv6 with TCP reset so clients fall back to standard DNS.
    """
    if IS_WINDOWS:
        return

    # 1. Enable IP forwarding
    _run_privileged(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"])
    _run_privileged(["sudo", "sysctl", "-w", "net.ipv6.conf.all.forwarding=1"])

    # 2. Port 53 DNS redirection
    iface = config.CAPTURE_INTERFACE if config.CAPTURE_INTERFACE else "wlan0"
    if is_port_53_listening():
        check_udp = _run_privileged(["sudo", "iptables", "-t", "nat", "-C", "PREROUTING", "-i", iface, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "53"])
        if not check_udp or check_udp.returncode != 0:
            _run_privileged(["sudo", "iptables", "-t", "nat", "-I", "PREROUTING", "1", "-i", iface, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "53"])
        check_tcp = _run_privileged(["sudo", "iptables", "-t", "nat", "-C", "PREROUTING", "-i", iface, "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "53"])
        if not check_tcp or check_tcp.returncode != 0:
            _run_privileged(["sudo", "iptables", "-t", "nat", "-I", "PREROUTING", "1", "-i", iface, "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "53"])
        print(f"[firewall] DNS redirection active on {iface}: all client port 53 queries sent to local sinkhole.")
    else:
        # Clean up any unconditional port 53 redirects that break outbound queries
        _run_privileged(["sudo", "iptables", "-t", "nat", "-D", "PREROUTING", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "53"])
        _run_privileged(["sudo", "iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "53"])
        _run_privileged(["sudo", "iptables", "-t", "nat", "-D", "PREROUTING", "-i", iface, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "53"])
        _run_privileged(["sudo", "iptables", "-t", "nat", "-D", "PREROUTING", "-i", iface, "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "53"])

    # 3. Block DNS-over-TLS (port 853) on IPv4 and IPv6 so mobile Private DNS falls back to standard DNS
    check_dot_v4 = _run_privileged(["sudo", "iptables", "-C", "FORWARD", "-p", "tcp", "--dport", "853", "-j", "REJECT", "--reject-with", "tcp-reset"])
    if not check_dot_v4 or check_dot_v4.returncode != 0:
        _run_privileged(["sudo", "iptables", "-I", "FORWARD", "1", "-p", "tcp", "--dport", "853", "-j", "REJECT", "--reject-with", "tcp-reset"])
        _run_privileged(["sudo", "iptables", "-I", "FORWARD", "1", "-p", "udp", "--dport", "853", "-j", "DROP"])

    check_dot_v6 = _run_privileged(["sudo", "ip6tables", "-C", "FORWARD", "-p", "tcp", "--dport", "853", "-j", "REJECT", "--reject-with", "tcp-reset"])
    if not check_dot_v6 or check_dot_v6.returncode != 0:
        _run_privileged(["sudo", "ip6tables", "-I", "FORWARD", "1", "-p", "tcp", "--dport", "853", "-j", "REJECT", "--reject-with", "tcp-reset"])
        _run_privileged(["sudo", "ip6tables", "-I", "FORWARD", "1", "-p", "udp", "--dport", "853", "-j", "DROP"])

    print("[firewall] Gateway firewall initialized: IP forwarding ON, DoT blocked.")


# ==============================================================================
# Public Enforcement Functions
# ==============================================================================

def enforce_block(value: str, entry_type: str):
    """Push a block rule down to the OS and gateway firewalls."""
    if entry_type == "ip":
        if IS_WINDOWS:
            _windows_add_ip_rule(f"GuardSpot_Block_IP_{value}", value)
        else:
            _add_iptables_drop(value)
        return

    # entry_type == "domain"
    # 1. Expand to all associated CDNs and streaming endpoints
    expanded_domains = get_expanded_domains(value)

    # 2. Block well-known service CIDR blocks (e.g. Meta AS32934 for Instagram/Facebook)
    cidrs = get_service_cidrs(value)
    safe_val = re.sub(r'[^a-zA-Z0-9.-]', '_', value)
    for cidr in cidrs:
        if IS_WINDOWS:
            _windows_add_ip_rule(f"GuardSpot_CIDR_{safe_val}_{cidr.replace('/', '_').replace(':', '_')}", cidr)
        else:
            _add_iptables_drop(cidr)

    # 3. Sinkhole each expanded domain in dnsmasq configs
    for dom in expanded_domains:
        _append_dnsmasq_rule(dom)

    # 4. Resolve only the root value and direct domain IPs (fast, non-blocking)
    root_ips = resolve_domain_ips(value)
    if IS_WINDOWS:
        for ip in root_ips:
            _windows_add_ip_rule(f"GuardSpot_Domain_{safe_val}_{ip}", ip)
    else:
        for ip in root_ips:
            _add_iptables_drop(ip)

    # 5. Reload dnsmasq once at the end and flush active connections
    if not IS_WINDOWS:
        _restart_dnsmasq()
        _run_privileged(["sudo", "conntrack", "-F"])


def unenforce_block(value: str, entry_type: str):
    """Remove a block rule from the OS and firewalls."""
    if entry_type == "ip":
        if IS_WINDOWS:
            _windows_remove_rules(f"GuardSpot_Block_IP_{value}")
        else:
            _remove_iptables_drop(value)
        return

    # entry_type == "domain"
    # 1. Remove CIDR blocks
    cidrs = get_service_cidrs(value)
    safe_val = re.sub(r'[^a-zA-Z0-9.-]', '_', value)
    for cidr in cidrs:
        if IS_WINDOWS:
            _windows_remove_rules(f"GuardSpot_CIDR_{safe_val}_{cidr.replace('/', '_').replace(':', '_')}")
        else:
            _remove_iptables_drop(cidr)

    # 2. Remove domain sinkhole & IP drops
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
    3. Layer 3/4 Firewall Dropping: Drops all incoming and outgoing packets (IPv4 and IPv6) by IP and MAC.
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

    # Linux / Raspberry Pi Gateway Firewall
    # 1. Kill active connection states immediately
    _run_privileged(["sudo", "conntrack", "-D", "-s", ip])
    _run_privileged(["sudo", "conntrack", "-D", "-d", ip])

    # 2. Firewall IP packet dropping at top of chains (IPv4)
    _run_privileged(["sudo", "iptables", "-I", "FORWARD", "1", "-s", ip, "-j", "DROP"])
    _run_privileged(["sudo", "iptables", "-I", "FORWARD", "1", "-d", ip, "-j", "DROP"])
    _run_privileged(["sudo", "iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"])
    _run_privileged(["sudo", "iptables", "-I", "OUTPUT", "1", "-d", ip, "-j", "DROP"])

    if mac:
        norm_mac = mac.upper()
        # 3. Firewall MAC packet dropping on both IPv4 and IPv6
        _run_privileged(["sudo", "iptables", "-I", "FORWARD", "1", "-m", "mac", "--mac-source", norm_mac, "-j", "DROP"])
        _run_privileged(["sudo", "iptables", "-I", "INPUT", "1", "-m", "mac", "--mac-source", norm_mac, "-j", "DROP"])
        _run_privileged(["sudo", "ip6tables", "-I", "FORWARD", "1", "-m", "mac", "--mac-source", norm_mac, "-j", "DROP"])
        _run_privileged(["sudo", "ip6tables", "-I", "INPUT", "1", "-m", "mac", "--mac-source", norm_mac, "-j", "DROP"])

        # 4. Layer 2 Wi-Fi Rejection: kick client from wireless driver (wlan0)
        for iface in ("wlan0", "ap0", config.CAPTURE_INTERFACE):
            _run_privileged(["sudo", "iw", "dev", iface, "station", "del", norm_mac.lower()])
            _run_privileged(["sudo", "iw", "dev", iface, "station", "del", norm_mac.upper()])

        # hostapd deny
        _hostapd_deny_add(norm_mac)

        # 5. DHCP Rejection: refuse to assign IP address to this MAC
        _dnsmasq_deny_add(norm_mac)


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
        norm_mac = mac.upper()
        _run_privileged(["sudo", "iptables", "-D", "FORWARD", "-m", "mac", "--mac-source", norm_mac, "-j", "DROP"])
        _run_privileged(["sudo", "iptables", "-D", "INPUT", "-m", "mac", "--mac-source", norm_mac, "-j", "DROP"])
        _run_privileged(["sudo", "ip6tables", "-D", "FORWARD", "-m", "mac", "--mac-source", norm_mac, "-j", "DROP"])
        _run_privileged(["sudo", "ip6tables", "-D", "INPUT", "-m", "mac", "--mac-source", norm_mac, "-j", "DROP"])
        _hostapd_deny_remove(norm_mac)
        _dnsmasq_deny_remove(norm_mac)
