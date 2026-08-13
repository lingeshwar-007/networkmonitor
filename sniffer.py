"""
sniffer.py
----------
Runs continuously on the Raspberry Pi. Captures DNS query packets on the
network interface, works out which device asked for which domain, checks
the domain against the blocklist, and writes an ActivityLog row.

This must run as root (packet capture needs raw socket access):
    sudo python3 sniffer.py

It shares the same Flask app + DB, so activity appears on the dashboard live.
"""

import datetime
from scapy.all import sniff, DNS, DNSQR, IP

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
    # Only interested in outgoing DNS *queries* (qr=0), not the responses.
    if not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR):
        return
    if pkt[DNS].qr != 0:
        return
    if not pkt.haslayer(IP):
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
            resolved_ip=None,  # filled in later if we see the DNS response
            status=status,
        )
        db.session.add(log_entry)
        db.session.commit()

        print(f"[{status.upper()}] {src_ip} -> {domain}")


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
