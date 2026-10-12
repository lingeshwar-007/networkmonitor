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
from models import BlockedEntry, Device
import validators
import config
import firewall

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
        "insta.com",
        "i.insta.com",
        "ig.com",
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
    "insta.com": [
        "instagram.com",
        "insta.com",
        "i.insta.com",
        "i.instagram.com",
        "cdninstagram.com",
        "ig.me",
        "fbcdn.net",
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

# Inverted index: maps any CDN or alias domain back to all parent root services
EXPANSION_TO_ROOTS = {}
for root, alts in DOMAIN_APP_EXPANSIONS.items():
    EXPANSION_TO_ROOTS.setdefault(root, set()).add(root)
    for alt in alts:
        EXPANSION_TO_ROOTS.setdefault(alt, set()).add(root)


def get_root_service(domain: str) -> str:
    """Return the parent service root domain if this is a known CDN or alternate domain."""
    roots = EXPANSION_TO_ROOTS.get(domain)
    return next(iter(roots)) if roots else None


def get_root_services(domain: str) -> list:
    """Return all parent service root domains for a given CDN or alternate domain."""
    return list(EXPANSION_TO_ROOTS.get(domain, set()))


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
    for r in get_root_services(norm):
        if r in SERVICE_CIDR_BLOCKS:
            return SERVICE_CIDR_BLOCKS[r]
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

    for r in get_root_services(norm):
        if r in DOMAIN_APP_EXPANSIONS:
            return list(set([r, norm] + DOMAIN_APP_EXPANSIONS[r]))
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
        clean_domain = validators.normalize_domain(domain).lower()
        parts = clean_domain.split(".")

        # 1. Candidate suffixes: e.g. for "instagram.fmaa1-2.fna.fbcdn.net" ->
        # ["instagram.fmaa1-2.fna.fbcdn.net", "fmaa1-2.fna.fbcdn.net", "fna.fbcdn.net", "fbcdn.net"]
        candidates = []
        for i in range(len(parts) - 1):
            candidates.append(".".join(parts[i:]))

        if candidates:
            # Check direct candidate matching in DB
            match = BlockedEntry.query.filter(
                BlockedEntry.entry_type == "domain",
                BlockedEntry.value.in_(candidates)
            ).first()
            if match:
                return True

            # 2. Service family expansion check (maps fbcdn.net -> {"instagram.com", "facebook.com"})
            root_candidates = set()
            for c in candidates:
                for r in get_root_services(c):
                    root_candidates.add(r)

            if root_candidates:
                match_root = BlockedEntry.query.filter(
                    BlockedEntry.entry_type == "domain",
                    BlockedEntry.value.in_(list(root_candidates))
                ).first()
                if match_root:
                    return True

        # 3. Direct active rule pattern matching:
        # If instagram.com or insta.com is blocked in the database:
        # Any domain containing "instagram", "cdninstagram", or ending in fbcdn.net / threads.net / ig.me / edge-mqtt.facebook.com is BLOCKED!
        try:
            active_domain_blocks = [e.value.lower() for e in BlockedEntry.query.filter_by(entry_type="domain").all()]
            for blocked_val in active_domain_blocks:
                if blocked_val in ("instagram.com", "insta.com"):
                    if (
                        "instagram" in clean_domain
                        or "cdninstagram" in clean_domain
                        or clean_domain.startswith("insta.")
                        or clean_domain.startswith("i.insta.")
                        or clean_domain.endswith(".fbcdn.net")
                        or clean_domain == "fbcdn.net"
                        or clean_domain.endswith(".threads.net")
                        or clean_domain.endswith(".ig.me")
                        or "edge-mqtt.facebook.com" in clean_domain
                    ):
                        return True
                elif blocked_val == "youtube.com":
                    if "googlevideo.com" in clean_domain or "ytimg.com" in clean_domain or "youtu.be" in clean_domain:
                        return True
                elif blocked_val == "tiktok.com":
                    if "tiktokcdn" in clean_domain or "byteoversea" in clean_domain or "ibytedtos" in clean_domain or "tiktokv" in clean_domain:
                        return True
                elif blocked_val == "facebook.com":
                    if "fbcdn.net" in clean_domain or "fbsbx.com" in clean_domain or "facebook.net" in clean_domain or "fb.me" in clean_domain:
                        return True
        except Exception:
            pass

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
        value, entry_type = entry.value, entry.entry_type
        db.session.delete(entry)
        db.session.commit()
        # Rules are rebuilt from the database, so un-enforce AFTER the row is gone.
        unenforce_block(value, entry_type)


def _run_privileged(cmd: list):
    """Run a command that needs root/admin. Never crashes Flask."""
    try:
        # If running as root on Linux, strip 'sudo' so it executes directly without TTY checks
        if platform.system() == "Linux" and cmd and cmd[0] == "sudo":
            if os.geteuid() == 0:
                cmd = cmd[1:]
            elif "-n" not in cmd[:2]:
                cmd = ["sudo", "-n"] + cmd[1:]  # never block waiting for a password prompt
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
    """Called when an IP for a blocked domain is detected in live traffic (Windows only).

    On the Linux gateway this is intentionally a no-op: the DNS sinkhole and the
    SNI/Host match already stop the site, while dropping the resolved IP of a site
    on shared CDN / Google / Cloudflare address space would also knock out
    unrelated sites that happen to share that IP.
    """
    if IS_WINDOWS:
        safe_domain = re.sub(r'[^a-zA-Z0-9.-]', '_', domain)
        _windows_add_ip_rule(f"GuardSpot_DomainIP_{safe_domain}_{ip}", ip)


# ==============================================================================
# Linux / Raspberry Pi Gateway Firewall
# All real enforcement lives in firewall.py. The database is the source of truth:
# after ANY change we rebuild the complete rule set from it (sync_firewall), so
# rules can never drift out of sync with what the dashboard shows.
# ==============================================================================

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


_last_sync = {"ok": None, "warnings": [], "counts": {}}


def _desired_state(extra_macs=()):
    """Read the COMPLETE desired firewall state from the database."""
    domains, cidrs, ips = set(), set(), []
    for e in BlockedEntry.query.all():
        if e.entry_type == "domain":
            domains.update(get_expanded_domains(e.value))
            cidrs.update(get_service_cidrs(e.value))
        else:
            ips.append(e.value)
    blocked = Device.query.filter_by(is_blocked=True).all()
    macs = {d.mac_address.upper() for d in blocked if d.mac_address}
    macs.update(m.upper() for m in extra_macs if m)
    # Only fall back to IP matching for devices whose MAC we never learned, so a
    # recycled DHCP address can never block an innocent new device.
    ip_only = {d.ip_address for d in blocked if not d.mac_address}
    return {"dns_domains": sorted(domains), "cidrs": sorted(cidrs), "block_ips": ips,
            "macs": sorted(macs), "device_ips": sorted(ip_only)}


def sync_firewall(flush_all=False, flush_ips=(), extra_macs=()):
    """
    Make the gateway match the database. Returns {"ok", "warnings", "counts"}.
    Must be called inside a Flask app context.
    """
    global _last_sync
    if IS_WINDOWS:
        return {"ok": True, "warnings": [], "counts": {}}
    state = _desired_state(extra_macs)
    result = firewall.apply(
        **state,
        iface=config.CAPTURE_INTERFACE,
        uplink=config.UPLINK_INTERFACE,
        block_doh=config.BLOCK_PUBLIC_DOH,
        block_dot=True,
        sni_filter=config.SNI_FILTER,
        block_quic=config.BLOCK_QUIC,
        flush_all=flush_all,
        flush_ips=flush_ips,
    )
    _last_sync = result
    for w in result.get("warnings", []):
        print(f"[firewall] WARNING: {w}")
    return result


def last_sync():
    return dict(_last_sync)


def firewall_status():
    """Health report for the dashboard: why a block would NOT be enforced."""
    if IS_WINDOWS:
        return firewall.status()
    domains = set()
    for e in BlockedEntry.query.filter_by(entry_type="domain").all():
        domains.update(get_expanded_domains(e.value))
    return firewall.status(
        iface=config.CAPTURE_INTERFACE,
        uplink=config.UPLINK_INTERFACE,
        expect_domains=sorted(domains),
        sni_filter=config.SNI_FILTER,
    )


def init_gateway_firewall():
    """Start-up plumbing that does not need the database (forwarding, NAT, conntrack)."""
    if IS_WINDOWS:
        return
    for w in firewall.init_system(config.CAPTURE_INTERFACE, config.UPLINK_INTERFACE):
        print(f"[firewall] WARNING: {w}")
    print("[firewall] Gateway plumbing initialised (IP forwarding, NAT, conntrack accounting).")


# ==============================================================================
# Public Enforcement Functions
# ==============================================================================

def enforce_block(value: str, entry_type: str):
    """Push a block rule down to the OS and gateway firewalls."""
    if not IS_WINDOWS:
        # flush_all: drop connections that are already open (e.g. a running video stream)
        return sync_firewall(flush_all=True)

    # ---- Windows (laptop hotspot): per-rule netsh firewall entries ----
    if entry_type == "ip":
        _windows_add_ip_rule(f"GuardSpot_Block_IP_{value}", value)
        return
    safe_val = re.sub(r'[^a-zA-Z0-9.-]', '_', value)
    for cidr in get_service_cidrs(value):
        _windows_add_ip_rule(f"GuardSpot_CIDR_{safe_val}_{cidr.replace('/', '_').replace(':', '_')}", cidr)
    for ip in resolve_domain_ips(value):
        _windows_add_ip_rule(f"GuardSpot_Domain_{safe_val}_{ip}", ip)


def unenforce_block(value: str, entry_type: str):
    """Remove a block rule from the OS and firewalls (call AFTER the DB row is deleted)."""
    if not IS_WINDOWS:
        return sync_firewall()

    if entry_type == "ip":
        _windows_remove_rules(f"GuardSpot_Block_IP_{value}")
        return
    safe_val = re.sub(r'[^a-zA-Z0-9.-]', '_', value)
    for cidr in get_service_cidrs(value):
        _windows_remove_rules(f"GuardSpot_CIDR_{safe_val}_{cidr.replace('/', '_').replace(':', '_')}")
    for dom in get_expanded_domains(value):
        safe_dom = re.sub(r'[^a-zA-Z0-9.-]', '_', dom)
        _windows_remove_rules(f"GuardSpot_Domain_{safe_dom}_*")
        _windows_remove_rules(f"GuardSpot_DomainIP_{safe_dom}_*")


# ==============================================================================
# Whole-Device Blocking / Unblocking
# ==============================================================================

def block_device(ip: str, mac: str = None):
    """
    Completely cuts a device off from the Wi-Fi network, local LAN, and internet.
    Call AFTER device.is_blocked has been committed to the database.
    1. Firewall: the device's MAC (or IP, if its MAC is unknown) is dropped in the
       GUARDSPOT chain at the top of FORWARD and INPUT - no traffic, no DHCP, no DNS.
    2. Active connections for its IP are killed immediately (conntrack).
    3. Wi-Fi: kicked from the access point and denied re-association (hostapd / iw).
    """
    if not mac:
        mac = lookup_mac(ip)

    print(f"[blocklist] Blocking entire device: IP={ip}, MAC={mac}")

    if IS_WINDOWS:
        _windows_add_ip_rule(f"GuardSpot_BlockDevice_{ip}", ip)
        _run_privileged(["netsh", "interface", "ip", "delete", "arpcache"])
        return

    result = sync_firewall(flush_ips=[ip], extra_macs=[mac] if mac else [])
    if mac:
        _hostapd_deny_add(mac.upper())
    return result


def unblock_device(ip: str, mac: str = None):
    """Restores network and Wi-Fi access. Call AFTER device.is_blocked=False is committed."""
    if not mac:
        mac = lookup_mac(ip)

    print(f"[blocklist] Unblocking device: IP={ip}, MAC={mac}")

    if IS_WINDOWS:
        _windows_remove_rules(f"GuardSpot_BlockDevice_{ip}")
        return

    result = sync_firewall()
    if mac:
        _hostapd_deny_remove(mac.upper())
    return result
