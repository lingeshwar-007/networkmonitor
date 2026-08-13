"""
seed_demo.py
------------
Populates the database with fake devices + activity + a couple of blocked
entries, purely so you can see the dashboard working end-to-end without
needing root access or real network traffic yet.

Run this ONCE after app.py has created the database:
    python3 seed_demo.py

Safe to delete afterwards — it's not part of the real running system.
"""

import random
import datetime

from app import create_app
from models import db, Device, ActivityLog, BlockedEntry

app = create_app()

DEMO_DEVICES = [
    ("192.168.1.10", "AA:BB:CC:11:22:33", "Lingesh's Laptop"),
    ("192.168.1.11", "AA:BB:CC:11:22:34", "Living Room TV"),
    ("192.168.1.12", "AA:BB:CC:11:22:35", "Guest Phone"),
]

DEMO_DOMAINS = [
    "youtube.com", "github.com", "instagram.com", "wikipedia.org",
    "netflix.com", "amazon.in", "chatgpt.com", "reddit.com",
    "ads.doubleclick.net", "trackers.example.com",
]

BLOCKED_DOMAINS = ["ads.doubleclick.net", "trackers.example.com"]

with app.app_context():
    db.create_all()

    devices = []
    for ip, mac, name in DEMO_DEVICES:
        device = Device.query.filter_by(ip_address=ip).first()
        if not device:
            device = Device(ip_address=ip, mac_address=mac, nickname=name)
            db.session.add(device)
        devices.append(device)
    db.session.commit()

    for domain in BLOCKED_DOMAINS:
        if not BlockedEntry.query.filter_by(value=domain).first():
            db.session.add(BlockedEntry(value=domain, entry_type="domain", reason="ads/tracking (demo)"))
    db.session.commit()

    now = datetime.datetime.utcnow()
    for i in range(40):
        device = random.choice(devices)
        domain = random.choice(DEMO_DOMAINS)
        status = "blocked" if domain in BLOCKED_DOMAINS else "allowed"
        log = ActivityLog(
            device_id=device.id,
            domain=domain,
            status=status,
            timestamp=now - datetime.timedelta(minutes=random.randint(0, 120)),
        )
        db.session.add(log)
    db.session.commit()

    print(f"Seeded {len(devices)} devices, {len(BLOCKED_DOMAINS)} blocklist entries, 40 activity logs.")
    print("Now run: python3 app.py  and open http://localhost:5000")
