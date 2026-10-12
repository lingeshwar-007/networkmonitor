"""
sniffer.py
----------
Runs continuously on the network host (Windows Mobile Hotspot or Raspberry Pi).
1. Captures DNS query packets (UDP port 53) on the network interface.
2. Identifies devices, automatically discovering MAC addresses and hostnames.
3. Enforces whole-device blocking: if a device is blocked by admin, its queries
   are immediately rejected (rcode=5) and Layer 2 / Layer 3 blocks prevent access.
4. Enforces website / app blocking: if a domain, subdomain, or app CDN is blocked,
   scapy instantly forges and returns a DNS sinkhole response (0.0.0.0 / NXDOMAIN)
   directly to the client before any upstream DNS server can answer.
5. Firewalls resolved IPs for defense-in-depth so cached DNS fails immediately.
6. Detects VPN / Proxy handshakes (WireGuard, OpenVPN, DoT, commercial VPNs).
7. Records all activity in the SQLite database for the Kali-themed dashboard.

Must run with elevated privileges:
- On Linux / Raspberry Pi: sudo python sniffer.py
- On Windows: Run PowerShell as Administrator, then python sniffer.py
"""

import os
import sys
import datetime
import subprocess
import platform
import socket
import re
from scapy.all import sniff, send, DNS, DNSQR, DNSRR, IP, UDP, TCP, conf

from app import create_app
from models import db, Device, ActivityLog, log_action
import blocklist
import vpn_detector
import config


app = create_app()
_resolved_iface = None
_last_lookup = {}  # ip -> time of last ARP/hostname lookup


def check_privileges():
    """Verify administrator or root privileges before attempting raw packet capture."""
    if platform.system() == "Windows":
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("\n" + "=" * 65)
                print(" [!] WARNING: Administrator privileges required on Windows!")
                print(" Please right-click PowerShell or CMD, select 'Run as Administrator',")
                print(" and re-run: python sniffer.py")
                print("=" * 65 + "\n")
        except Exception:
            pass
    else:
        # Linux / Raspberry Pi / macOS
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            print("\n" + "=" * 65)
            print(" [!] ERROR: Root privileges required for raw packet sniffing.")
            print(" Please re-run with sudo:")
            print("     sudo python3 sniffer.py")
            print("=" * 65 + "\n")
            sys.exit(1)


def lookup_mac(ip: str) -> str:
    """Find MAC address for an IP from the system ARP table."""
    try:
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


def lookup_hostname(ip: str) -> str:
    """Attempt reverse DNS lookup with short timeout."""
    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(0.3)
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            return host.split(".")[0]
        finally:
            socket.setdefaulttimeout(old_timeout)
    except Exception:
        return None


def get_or_create_device(ip_address: str) -> Device:
    """
    Lookup or insert device, enriching with MAC address and hostname.
    If a device with the same MAC address was previously blocked and renewed its IP,
    its block is automatically transferred and re-enforced on the new IP.
    """
    now = datetime.datetime.utcnow()
    device = Device.query.filter_by(ip_address=ip_address).first()

    # ARP / reverse-DNS lookups are slow (up to 0.3 s) and this runs inside the packet
    # callback, which delayed the forged DNS replies. Only look up what is still missing,
    # and not more than once a minute per IP.
    need_mac = device is None or not device.mac_address
    need_host = device is None or not device.nickname
    if (need_mac or need_host) and now.timestamp() - _last_lookup.get(ip_address, 0) < 60 and device is not None:
        need_mac = need_host = False
    if need_mac or need_host:
        _last_lookup[ip_address] = now.timestamp()
    mac = lookup_mac(ip_address) if need_mac else None
    hostname = lookup_hostname(ip_address) if need_host else None

    if device is None:
        # Check if this hardware MAC was already recorded under an older IP
        if mac:
            existing_by_mac = Device.query.filter_by(mac_address=mac).first()
            if existing_by_mac:
                device = existing_by_mac
                old_ip = device.ip_address
                device.ip_address = ip_address
                device.last_seen = now
                if hostname and not device.nickname:
                    device.nickname = hostname
                db.session.commit()
                if device.is_blocked:
                    # Device changed IP while blocked! Re-enforce immediately on new IP
                    blocklist.block_device(ip_address, mac)
                    print(f"[DEVICE BLOCKED] {mac} changed IP {old_ip} -> {ip_address}; block re-enforced!")
                return device

        device = Device(
            ip_address=ip_address,
            mac_address=mac,
            nickname=hostname,
            first_seen=now,
            last_seen=now,
            is_blocked=False,
        )
        db.session.add(device)
    else:
        device.last_seen = now
        if not device.mac_address and mac:
            device.mac_address = mac
        if not device.nickname and hostname:
            device.nickname = hostname

    db.session.commit()
    return device


def send_dns_sinkhole(pkt, qname: bytes, qtype: int, rcode: int = 0):
    """
    Sends an immediate spoofed DNS response back to the client.
    Because this packet is generated locally, it arrives in <1ms,
    beating any upstream DNS response and poisoning the client cache to 0.0.0.0.
    """
    global _resolved_iface
    try:
        if not pkt.haslayer(IP) or not pkt.haslayer(UDP) or not pkt.haslayer(DNS):
            return

        if rcode == 0:
            if qtype == 1:  # IPv4 A record
                an = DNSRR(rrname=qname, type=1, rclass=1, ttl=300, rdata="0.0.0.0")
                ancount = 1
            elif qtype == 28:  # IPv6 AAAA record
                an = DNSRR(rrname=qname, type=28, rclass=1, ttl=300, rdata="::")
                ancount = 1
            elif qtype == 65:  # HTTPS SVCB record (used by modern browsers / iOS)
                an = None
                ancount = 0
                rcode = 3  # NXDOMAIN so client doesn't use encrypted transport hints
            else:
                an = DNSRR(rrname=qname, type=qtype, rclass=1, ttl=300, rdata="0.0.0.0")
                ancount = 1
        else:
            an = None
            ancount = 0

        resp = (
            IP(src=pkt[IP].dst, dst=pkt[IP].src)
            / UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
            / DNS(
                id=pkt[DNS].id,
                qr=1,      # Response
                aa=1,      # Authoritative Answer
                tc=0,
                rd=pkt[DNS].rd,
                ra=1,
                rcode=rcode,
                qd=pkt[DNS].qd,
                an=an,
                ancount=ancount,
                nscount=0,
                arcount=0,
            )
        )

        send(resp, iface=_resolved_iface, verbose=False)
    except Exception as e:
        print(f"[sniffer] Error sending DNS sinkhole response: {e}")


def handle_potential_vpn(pkt):
    """Detect packets destined for known VPN / encrypted tunnel handshake ports."""
    dport = None
    if pkt.haslayer(UDP):
        dport = pkt[UDP].dport
    elif pkt.haslayer(TCP):
        dport = pkt[TCP].dport

    if not dport or dport == 53:
        return

    vpn_name = vpn_detector.detect_vpn_port(dport)
    if vpn_name:
        src_ip = pkt[IP].src
        with app.app_context():
            db.session.expire_all()
            device = get_or_create_device(src_ip)
            if not device.vpn_detected or device.vpn_type != vpn_name:
                device.vpn_detected = True
                device.vpn_type = vpn_name
                db.session.commit()
                print(f"[VPN DETECTED] {src_ip} ({device.nickname or 'device'}) -> {vpn_name} on port {dport}!")


def handle_packet(pkt):
    if not pkt.haslayer(IP):
        return

    # Check for DNS
    if pkt.haslayer(DNS):
        if pkt[DNS].qr == 0:
            handle_query(pkt)
        else:
            handle_response(pkt)
        return

    # Check for VPN handshake ports
    handle_potential_vpn(pkt)


def handle_query(pkt):
    if not pkt.haslayer(DNSQR):
        return

    src_ip = pkt[IP].src
    domain = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
    qtype = pkt[DNSQR].qtype

    with app.app_context():
        db.session.expire_all()
        device = get_or_create_device(src_ip)

        # 1. Whole-device block check
        if device.is_blocked:
            # Refuse DNS queries from blocked device
            send_dns_sinkhole(pkt, pkt[DNSQR].qname, qtype, rcode=5)  # Refused
            log_entry = ActivityLog(
                device_id=device.id,
                domain=domain,
                resolved_ip="0.0.0.0",
                status="blocked",
            )
            db.session.add(log_entry)
            db.session.commit()
            print(f"[DEVICE BLOCKED] {src_ip} ({device.nickname or 'unknown'}) -> {domain}")
            return

        # 2. VPN Domain lookup detection & auto-sinkhole
        vpn_service = vpn_detector.detect_vpn_domain(domain)
        if vpn_service:
            device.vpn_detected = True
            device.vpn_type = vpn_service
            db.session.commit()
            # Sinkhole the query to prevent VPN server connection
            send_dns_sinkhole(pkt, pkt[DNSQR].qname, qtype, rcode=0)
            log_entry = ActivityLog(
                device_id=device.id,
                domain=domain,
                resolved_ip="0.0.0.0",
                status="blocked",
            )
            db.session.add(log_entry)
            db.session.commit()
            print(f"[VPN BLOCKED] {src_ip} -> {domain} ({vpn_service} lookup sinkholed)")
            return

        # 3. Website & App block check (includes CDNs e.g. i.instagram.com, googlevideo.com, etc.)
        is_dom_blocked = blocklist.is_blocked(domain)
        if is_dom_blocked:
            # Active DNS Sinkhole: respond with 0.0.0.0 immediately
            send_dns_sinkhole(pkt, pkt[DNSQR].qname, qtype, rcode=0)

            # OPTIONAL AUTO-DEFENSE / QUARANTINE (off by default, see config.AUTO_QUARANTINE):
            # when enabled, a device that tries to use a blocked service (web or app)
            # is isolated from the whole network. When disabled, only the site is blocked.
            if config.AUTO_QUARANTINE and not device.is_blocked:
                device.is_blocked = True
                if not device.mac_address:
                    resolved_mac = blocklist.lookup_mac(src_ip)
                    if resolved_mac:
                        device.mac_address = resolved_mac
                db.session.commit()
                blocklist.block_device(src_ip, device.mac_address)
                dev_label = device.nickname or device.mac_address or src_ip
                try:
                    log_action("AUTO_FIREWALL", f"AUTO_BLOCKED_DEVICE: {dev_label} ({src_ip}) for accessing blocked {domain}")
                except Exception:
                    pass
                print(f"[AUTO-DEFENSE TRIGGERED] {src_ip} ({dev_label}) tried accessing '{domain}'! Device has been IMMEDIATELY CUT OFF and KICKED from Wi-Fi!")

            log_entry = ActivityLog(
                device_id=device.id,
                domain=domain,
                resolved_ip="0.0.0.0",
                status="blocked",
            )
            db.session.add(log_entry)
            db.session.commit()
            print(f"[WEBSITE & APP BLOCKED] {src_ip} -> {domain} (sinkholed"
                  f"{' & device isolated' if config.AUTO_QUARANTINE else ''})")
            return

        # 4. Allowed request
        log_entry = ActivityLog(
            device_id=device.id,
            domain=domain,
            resolved_ip=None,
            status="allowed",
        )
        db.session.add(log_entry)
        db.session.commit()
        print(f"[ALLOWED] {src_ip} -> {domain}")


def handle_response(pkt):
    """Watch DNS responses to dynamically firewall newly discovered IPs for blocked domains.

    Windows only. On the Linux gateway the DNS sinkhole + SNI/Host match in firewall.py
    do the job, and dropping resolved IPs of shared CDNs would break unrelated sites.
    """
    if not blocklist.IS_WINDOWS:
        return
    if not pkt.haslayer(DNSRR):
        return
    try:
        domain = pkt[DNS].qd.qname.decode(errors="ignore").rstrip(".")
    except (AttributeError, IndexError):
        return

    with app.app_context():
        db.session.expire_all()
        if not blocklist.is_blocked(domain):
            return

        for i in range(pkt[DNS].ancount):
            rr = pkt[DNS].an[i]
            if rr.type in (1, 28):  # 1 = IPv4 A record, 28 = IPv6 AAAA record
                resolved_ip = rr.rdata
                if resolved_ip and resolved_ip not in ("0.0.0.0", "::"):
                    blocklist.enforce_domain_ip(domain, resolved_ip)
                    print(f"[FIREWALL SYNC] {domain} -> {resolved_ip} blocked at firewall")


def resolve_iface(value):
    """Resolve adapter index, IP, or name to scapy interface object."""
    if isinstance(value, int):
        return conf.ifaces.dev_from_index(value)
    for i in conf.ifaces.values():
        if getattr(i, "ip", None) == value:
            return i
        if getattr(i, "name", None) == value:
            return i
    return value


def main():
    global _resolved_iface
    check_privileges()
    _resolved_iface = resolve_iface(config.CAPTURE_INTERFACE)
    print(f"==================================================")
    print(f" GuardSpot Sniffer & Active Enforcement Engine")
    print(f"==================================================")
    print(f" Interface : {config.CAPTURE_INTERFACE} -> {_resolved_iface}")
    print(f" Filter    : {config.CAPTURE_FILTER}")
    print(f" Mode      : {'Raspberry Pi' if config.IS_PI else 'Windows Laptop'}")
    print(f" Active DNS Sinkholing: ENABLED")
    print(f" Press Ctrl+C to stop.\n")

    sniff(
        iface=_resolved_iface,
        filter=config.CAPTURE_FILTER,
        prn=handle_packet,
        store=False,
    )


if __name__ == "__main__":
    main()
