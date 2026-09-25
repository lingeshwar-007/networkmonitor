"""
sniffer.py
----------
Runs continuously on the network host. Captures DNS query packets on the
network interface, works out which device asked for which domain, checks
the domain against the blocklist, and writes an ActivityLog row.
Also watches DNS *responses* so blocked domains can be firewalled by IP
(needed on Windows, which has no dnsmasq to refuse resolution outright).

This must run elevated (raw socket access + firewall changes):
    python sniffer.py   (as Administrator / with sudo)

It shares the same Flask app + DB, so activity appears on the dashboard live.
"""

import datetime
from scapy.all import sniff, DNS, DNSQR, DNSRR, IP

from app import create_app
from models import db, Device, ActivityLog
import blocklist
import config

app = create_app()


def get_or_create_device(ip_address):
    device = Device.query.filter_by(ip_address=ip_address).first()
    now = datetime.datetime.utcnow()
    if device is None:
        device = Device(ip_address=ip_address, first_seen=now, last_seen=now)
        db.session.add(device)
    else:
        device.last_seen = now
    db.session.commit()
    return device


def handle_packet(pkt):
    if not pkt.haslayer(DNS) or not pkt.haslayer(IP):
        return
    if pkt[DNS].qr == 0:
        handle_query(pkt)
    else:
        handle_response(pkt)


def handle_query(pkt):
    if not pkt.haslayer(DNSQR):
        return
    src_ip = pkt[IP].src
    domain = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")

    with app.app_context():
        device = get_or_create_device(src_ip)
        blocked = blocklist.is_blocked(domain)
        status = "blocked" if blocked else "allowed"

        log_entry = ActivityLog(
            device_id=device.id,
            domain=domain,
            resolved_ip=None,
            status=status,
        )
        db.session.add(log_entry)
        db.session.commit()

        print(f"[{status.upper()}] {src_ip} -> {domain}")


def handle_response(pkt):
    """Windows-only: watch DNS responses to learn which IP a blocked
    domain resolved to, then ask blocklist.py to firewall that IP."""
    if not pkt.haslayer(DNSRR):
        return
    try:
        domain = pkt[DNS].qd.qname.decode(errors="ignore").rstrip(".")
    except (AttributeError, IndexError):
        return

    with app.app_context():
        if not blocklist.is_blocked(domain):
            return
        for i in range(pkt[DNS].ancount):
            rr = pkt[DNS].an[i]
            if rr.type == 1:  # A record
                resolved_ip = rr.rdata
                blocklist.enforce_domain_ip(domain, resolved_ip)
                print(f"[FIREWALL] {domain} -> {resolved_ip} blocked")


def main():
    print(f"GuardSpot sniffer starting on interface: {config.CAPTURE_INTERFACE}")
    print(f"Filter: {config.CAPTURE_FILTER}")
    print("Press Ctrl+C to stop.\n")
    sniff(
        iface=config.CAPTURE_INTERFACE,
        filter=config.CAPTURE_FILTER,
        prn=handle_packet,
        store=False,
    )


if __name__ == "__main__":
    main()
