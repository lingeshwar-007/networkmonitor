"""
app.py
------
The web application (admin-only dashboard). This is the file you run with:
    python3 app.py
It does NOT capture packets itself — that's sniffer.py's job, running as a
separate process. app.py just reads/writes the same database and serves it
as a website.
"""

from functools import wraps
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from models import db, Device, ActivityLog, BlockedEntry, AuditLog, log_action
from tunnel import connect_ssh, start_forward
import blocklist as blocklist_module
import validators
import config

_active_ssh_client = None  # keeps the SSH connection alive once established

# ---- Brute-force lockout for /login ----
# Tracks failed SSH attempts per source IP in memory. After too many
# failures, that IP is locked out for a cooldown period regardless of
# whether the credentials it's now sending are correct.
_failed_attempts = {}  # { ip: [timestamp, timestamp, ...] }
MAX_ATTEMPTS = 5
LOCKOUT_WINDOW = timedelta(minutes=10)


def _is_locked_out(ip: str) -> bool:
    attempts = _failed_attempts.get(ip, [])
    cutoff = datetime.utcnow() - LOCKOUT_WINDOW
    attempts = [t for t in attempts if t > cutoff]
    _failed_attempts[ip] = attempts
    return len(attempts) >= MAX_ATTEMPTS


def _record_failed_attempt(ip: str):
    _failed_attempts.setdefault(ip, []).append(datetime.utcnow())


def create_app():
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = config.SQLALCHEMY_DATABASE_URI
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SECRET_KEY"] = config.SECRET_KEY

    # Defense-in-depth session cookie settings
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    db.init_app(app)

    with app.app_context():
        db.create_all()

    limiter = Limiter(get_remote_address, app=app, default_limits=["200 per hour"])

    register_routes(app, limiter)
    return app


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        # Anyone reaching us on loopback got here through the SSH tunnel —
        # SSH already authenticated them, so trust it. This ONLY applies
        # on the Pi-hosted instance (config.IS_PI=True) — on your laptop,
        # your own browser hitting localhost is not an SSH tunnel and must
        # still go through the login page.
        if config.IS_PI and request.remote_addr in ("127.0.0.1", "::1") and not session.get("is_admin"):
            session["is_admin"] = True
            session["username"] = "admin (via SSH)"
        if not session.get("is_admin"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def register_routes(app, limiter):

    # ---- Auth: log in by SSHing into the Pi, not a stored password ----
    # Rate-limited to blunt brute-force/credential-stuffing attempts, plus
    # a per-IP lockout on top after repeated failures.
    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("10 per minute")
    def login():
        global _active_ssh_client

        if request.method == "POST":
            client_ip = get_remote_address()

            if _is_locked_out(client_ip):
                return render_template(
                    "login.html",
                    error="Too many failed attempts. Try again in a few minutes."
                ), 429

            pi_ip = request.form.get("pi_ip", "").strip()
            ssh_username = request.form.get("ssh_username", "").strip()
            auth_method = request.form.get("auth_method", "password")
            password = request.form.get("password", "")
            key_path = request.form.get("key_path", "").strip()

            # Validate shape before it ever reaches paramiko/SSH.
            if not validators.is_valid_ipv4(pi_ip):
                return render_template("login.html", error="Enter a valid IPv4 address, e.g. 192.168.4.1.")
            if not validators.is_valid_ssh_username(ssh_username):
                return render_template("login.html", error="SSH username looks invalid.")

            try:
                client = connect_ssh(
                    pi_ip=pi_ip,
                    ssh_username=ssh_username,
                    password=password if auth_method == "password" else None,
                    key_path=key_path if auth_method == "key" else None,
                )
            except Exception as e:
                _record_failed_attempt(client_ip)
                return render_template("login.html", error=f"Couldn't connect over SSH: {e}")

            _active_ssh_client = client
            transport = client.get_transport()
            start_forward(config.TUNNEL_LOCAL_PORT, "127.0.0.1", config.PORT, transport)

            log_action(ssh_username, f"SSH_CONNECT:{pi_ip}")
            return redirect(f"http://localhost:{config.TUNNEL_LOCAL_PORT}/")

        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # ---- Dashboard pages ----
    @app.route("/")
    @login_required
    def dashboard():
        return render_template("dashboard.html", username=session.get("username", config.ADMIN_USERNAME))

    # ---- JSON API consumed by the dashboard's JS ----
    @app.route("/api/devices")
    @login_required
    def api_devices():
        devices = Device.query.order_by(Device.last_seen.desc()).all()
        return jsonify([d.to_dict() for d in devices])

    @app.route("/api/devices/<int:device_id>/block", methods=["POST"])
    @login_required
    @limiter.limit("30 per minute")
    def api_device_block(device_id):
        device = Device.query.get_or_404(device_id)
        device.is_blocked = True
        db.session.commit()
        blocklist_module.block_device(device.ip_address)
        log_action(session.get("username", "admin"), f"BLOCK_DEVICE:{device.mac_address or device.ip_address}")
        return jsonify(device.to_dict())

    @app.route("/api/devices/<int:device_id>/unblock", methods=["POST"])
    @login_required
    @limiter.limit("30 per minute")
    def api_device_unblock(device_id):
        device = Device.query.get_or_404(device_id)
        device.is_blocked = False
        db.session.commit()
        blocklist_module.unblock_device(device.ip_address)
        log_action(session.get("username", "admin"), f"UNBLOCK_DEVICE:{device.mac_address or device.ip_address}")
        return jsonify(device.to_dict())

    @app.route("/api/activity")
    @login_required
    def api_activity():
        device_id = request.args.get("device_id", type=int)
        limit = request.args.get("limit", default=100, type=int)
        offset = request.args.get("offset", default=0, type=int)

        query = ActivityLog.query.order_by(ActivityLog.timestamp.desc())
        if device_id:
            query = query.filter_by(device_id=device_id)

        logs = query.offset(offset).limit(limit).all()
        return jsonify([log.to_dict() for log in logs])

    @app.route("/api/blocklist", methods=["GET", "POST"])
    @login_required
    def api_blocklist():
        if request.method == "POST":
            data = request.get_json(force=True, silent=True) or {}
            value = data.get("value", "").strip().lower()
            entry_type = data.get("entry_type", "domain")
            reason = data.get("reason", "")[:255]  # cap length regardless of validity

            if entry_type not in ("domain", "ip"):
                return jsonify({"error": "entry_type must be 'domain' or 'ip'"}), 400
            if not validators.is_valid_block_value(value, entry_type):
                return jsonify({"error": f"'{value}' doesn't look like a valid {entry_type}"}), 400

            entry = blocklist_module.add_block(value, entry_type, reason, db=db)
            log_action(session.get("username", "admin"), f"BLOCK_WEBSITE:{value}")
            return jsonify(entry.to_dict()), 201

        entries = BlockedEntry.query.order_by(BlockedEntry.added_at.desc()).all()
        return jsonify([e.to_dict() for e in entries])

    @app.route("/api/blocklist/<int:entry_id>", methods=["DELETE"])
    @login_required
    def api_blocklist_delete(entry_id):
        entry = BlockedEntry.query.get(entry_id)
        value = entry.value if entry else str(entry_id)
        blocklist_module.remove_block(entry_id, db=db)
        log_action(session.get("username", "admin"), f"UNBLOCK_WEBSITE:{value}")
        return jsonify({"success": True})

    @app.route("/api/audit-log")
    @login_required
    def api_audit_log():
        limit = request.args.get("limit", default=50, type=int)
        entries = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(limit).all()
        return jsonify([e.to_dict() for e in entries])

    @app.route("/api/stats")
    @login_required
    def api_stats():
        devices = Device.query.all()
        connected_now = sum(1 for d in devices if d.to_dict()["connected"])
        return jsonify({
            "known_devices": len(devices),
            "connected_now": connected_now,
            "active_block_rules": BlockedEntry.query.count(),
            "blocked_requests": ActivityLog.query.filter_by(status="blocked").count(),
        })


if __name__ == "__main__":
    app = create_app()
    # debug=False in production — Flask's debugger exposes a Python shell
    # to anyone who can reach an error page if left on.
    debug_mode = config.__dict__.get("DEBUG", False)
    app.run(host=config.HOST, port=config.PORT, debug=debug_mode)
