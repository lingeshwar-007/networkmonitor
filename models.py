"""
models.py
---------
Database schema (SQLAlchemy ORM). Four tables:

Device       -> every unique client IP/MAC seen on the network
ActivityLog  -> one row per DNS request observed (the "what did the user visit" log)
BlockedEntry -> domains/IPs the admin has chosen to block
AuditLog     -> every admin action (logins, device blocks, website blocks)
"""

from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# A device counts as "connected" if we've seen traffic from it within this window.
ONLINE_THRESHOLD = timedelta(seconds=90)


class Device(db.Model):
    __tablename__ = "devices"

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    mac_address = db.Column(db.String(17), nullable=True)
    nickname = db.Column(db.String(80), nullable=True)  # hostname, e.g. "EDITH"
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    is_blocked = db.Column(db.Boolean, default=False, nullable=False)  # whole-device block

    logs = db.relationship("ActivityLog", backref="device", lazy="dynamic")

    def to_dict(self):
        is_connected = (datetime.utcnow() - self.last_seen) < ONLINE_THRESHOLD
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "hostname": self.nickname or self.ip_address,
            "nickname": self.nickname or self.ip_address,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "is_blocked": self.is_blocked,
            "connected": is_connected,
        }


class ActivityLog(db.Model):
    __tablename__ = "activity_log"

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id"), nullable=False)
    domain = db.Column(db.String(255), nullable=False)
    resolved_ip = db.Column(db.String(45), nullable=True)
    status = db.Column(db.String(10), nullable=False, default="allowed")  # allowed | blocked
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "device_id": self.device_id,
            "device": self.device.nickname or self.device.ip_address,
            "domain": self.domain,
            "resolved_ip": self.resolved_ip,
            "status": self.status,
            "timestamp": self.timestamp.isoformat(),
        }


class BlockedEntry(db.Model):
    __tablename__ = "blocked_entries"

    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(255), nullable=False, unique=True)  # domain or IP
    entry_type = db.Column(db.String(10), nullable=False)  # "domain" | "ip"
    reason = db.Column(db.String(255), nullable=True)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "value": self.value,
            "entry_type": self.entry_type,
            "reason": self.reason,
            "added_at": self.added_at.isoformat(),
        }


class AuditLog(db.Model):
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    actor = db.Column(db.String(80), nullable=False)       # who did it, e.g. "admin"
    action = db.Column(db.String(255), nullable=False)     # e.g. "BLOCK_DEVICE:9C:C7:D3:8B:48:D8"
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "actor": self.actor,
            "action": self.action,
            "timestamp": self.timestamp.isoformat(),
        }


def log_action(actor: str, action: str):
    """Convenience helper — call this anywhere an admin action happens."""
    entry = AuditLog(actor=actor, action=action)
    db.session.add(entry)
    db.session.commit()
