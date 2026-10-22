"""
app.py
------
The web application (admin-only dashboard). This is the file you run with:
    python app.py
It reads/writes the shared SQLite database and serves the management dashboard.
Enforces whole-device blocking and domain/app blocking via blocklist.py.
"""

from functools import wraps
from datetime import datetime, timedelta
import secrets
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
    if not config.SECRET_KEY:
        config.SECRET_KEY = secrets.token_hex(32)

    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = config.SQLALCHEMY_DATABASE_URI
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SECRET_KEY"] = config.SECRET_KEY

    # Defense-in-depth session cookie settings
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = config.SESSION_COOKIE_SECURE

    @app.before_request
    def protect_state_changing_requests():
        if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
            return None
        if request.endpoint == "login":
            return None
        expected = session.get("csrf_token")
        supplied = request.headers.get("X-CSRFToken") or request.form.get("csrf_token")
        if not expected or not supplied or not secrets.compare_digest(supplied, expected):
            return jsonify({"error": "CSRF validation failed"}), 403
        return None

    db.init_app(app)

    with app.app_context():
        db.create_all()
        # Enable WAL mode for high-concurrency access between sniffer and web app
        try:
            db.session.execute(db.text("PRAGMA journal_mode=WAL;"))
            db.session.commit()
        except Exception:
            pass

        # Auto-migrate devices table for VPN detection if needed
        try:
            db.session.execute(db.text("ALTER TABLE devices ADD COLUMN vpn_detected BOOLEAN DEFAULT 0;"))
            db.session.commit()
        except Exception:
            pass
        try:
            db.session.execute(db.text("ALTER TABLE devices ADD COLUMN vpn_type VARCHAR(80);"))
            db.session.commit()
        except Exception:
            pass
        try:
            db.session.execute(db.text("ALTER TABLE activity_log ADD COLUMN application_name VARCHAR(100);"))
            db.session.commit()
        except Exception:
            pass


    limiter = Limiter(get_remote_address, app=app, default_limits=["12000 per hour"])

    register_routes(app, limiter)
    return app


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        # On the Raspberry Pi, local loopback represents an established SSH tunnel
        if config.IS_PI and request.remote_addr in ("127.0.0.1", "::1") and not session.get("is_admin"):
            session["is_admin"] = True
            session["username"] = "admin (via SSH)"
        if not session.get("is_admin"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def register_routes(app, limiter):

    @app.errorhandler(429)
    def ratelimit_handler(e):
        if request.path == "/login":
            return render_template(
                "login.html",
                error="Rate limit exceeded: Too many attempts. Please wait 1 minute before retrying.",
                is_pi=config.IS_PI,
                config_pi_host=config.PI_HOSTNAME,
            ), 429
        return jsonify({"error": "Rate limit exceeded. Please wait a moment before retrying."}), 429

    # ---- Auth: log in locally or over SSH ----
    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("30 per minute", methods=["POST"])
    def login():
        global _active_ssh_client

        # If already logged in, go straight to dashboard
        if session.get("is_admin"):
            return redirect(url_for("dashboard"))

        # If connected through loopback on the Pi (SSH port-forward or local on Pi), auto-login
        if config.IS_PI and request.remote_addr in ("127.0.0.1", "::1"):
            session["is_admin"] = True
            session["username"] = "admin (via SSH)"
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            username = (
                request.form.get("username")
                or request.form.get("ssh_username")
                or ""
            ).strip()
            password = request.form.get("password", "")
            pi_ip = request.form.get("pi_ip", "").strip()
            auth_method = request.form.get("auth_method", "password")
            key_path = request.form.get("key_path", "").strip()

            # 1. Local admin credentials (default: admin / admin)
            admin_pwd = config.ADMIN_PASSWORD or "admin"
            if username.lower() == config.ADMIN_USERNAME.lower() and password == admin_pwd and not pi_ip:
                session["is_admin"] = True
                session["username"] = username
                log_action(username, "ADMIN_LOGIN")
                return redirect(url_for("dashboard"))

            # 2. Remote Host / Raspberry Pi SSH authentication
            ssh_err = None
            ssh_host = pi_ip if (pi_ip and validators.is_valid_host(pi_ip)) else config.PI_HOSTNAME
            if username and pi_ip:
                try:
                    client = connect_ssh(
                        pi_ip=ssh_host,
                        ssh_username=username,
                        password=password if auth_method == "password" else None,
                        key_path=key_path if auth_method == "key" else None,
                    )
                    session["is_admin"] = True
                    session["username"] = f"{username} (via SSH)"
                    log_action(username, f"SSH_AUTH_SUCCESS:{ssh_host}")

                    # If running on laptop, forward tunnel to Pi's live web dashboard
                    if not config.IS_PI:
                        global _active_ssh_client
                        _active_ssh_client = client
                        transport = client.get_transport()
                        try:
                            start_forward(config.TUNNEL_LOCAL_PORT, "127.0.0.1", config.PORT, transport)
                        except Exception:
                            pass
                        import time
                        time.sleep(1.0)
                        return redirect(f"http://localhost:{config.TUNNEL_LOCAL_PORT}/")

                    client.close()
                    return redirect(url_for("dashboard"))
                except Exception as e:
                    ssh_err = str(e)

            if ssh_err:
                err_msg = f"SSH connection to {ssh_host} failed: {ssh_err}. Check your Host IP and credentials."
            else:
                err_msg = "Invalid credentials. Use 'admin' / 'admin' for local dashboard, or enter Host IP and SSH credentials."

            return render_template(
                "login.html",
                error=err_msg,
                is_pi=config.IS_PI,
                config_pi_host=config.PI_HOSTNAME,
            )

        session.setdefault("csrf_token", secrets.token_urlsafe(32))
        return render_template("login.html", is_pi=config.IS_PI, config_pi_host=config.PI_HOSTNAME)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # ---- Dashboard pages ----
    @app.route("/")
    @login_required
    def dashboard():
        return render_template(
            "dashboard.html",
            username=session.get("username", config.ADMIN_USERNAME),
            is_pi=config.IS_PI,
            csrf_token=session.setdefault("csrf_token", secrets.token_urlsafe(32)),
        )


    # ---- JSON API consumed by dashboard.js ----
    @app.route("/api/devices")
    @login_required
    def api_devices():
        db.session.expire_all()
        devices = Device.query.order_by(Device.last_seen.desc()).all()
        return jsonify([d.to_dict() for d in devices])

    @app.route("/api/devices/<int:device_id>/block", methods=["POST"])
    @login_required
    @limiter.limit("60 per minute")
    def api_device_block(device_id):
        device = Device.query.get_or_404(device_id)
        device.is_blocked = True
        if not device.mac_address:
            resolved_mac = blocklist_module.lookup_mac(device.ip_address)
            if resolved_mac:
                device.mac_address = resolved_mac
        db.session.commit()
        blocklist_module.block_device(device.ip_address, device.mac_address)
        dev_label = device.nickname or device.mac_address or device.ip_address
        log_action(session.get("username", "admin"), f"BLOCK_DEVICE:{dev_label} ({device.ip_address})")
        return jsonify(device.to_dict())

    @app.route("/api/devices/<int:device_id>/unblock", methods=["POST"])
    @login_required
    @limiter.limit("60 per minute")
    def api_device_unblock(device_id):
        device = Device.query.get_or_404(device_id)
        device.is_blocked = False
        db.session.commit()
        blocklist_module.unblock_device(device.ip_address, device.mac_address)
        dev_label = device.nickname or device.mac_address or device.ip_address
        log_action(session.get("username", "admin"), f"UNBLOCK_DEVICE:{dev_label} ({device.ip_address})")
        return jsonify(device.to_dict())

    @app.route("/api/devices/<int:device_id>/clear-vpn", methods=["POST"])
    @login_required
    def api_device_clear_vpn(device_id):
        device = Device.query.get_or_404(device_id)
        device.vpn_detected = False
        device.vpn_type = None
        db.session.commit()
        dev_label = device.nickname or device.mac_address or device.ip_address
        log_action(session.get("username", "admin"), f"CLEAR_VPN_ALERT:{dev_label} ({device.ip_address})")
        return jsonify(device.to_dict())


    @app.route("/api/activity")
    @login_required
    def api_activity():
        db.session.expire_all()
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
        db.session.expire_all()
        if request.method == "POST":
            data = request.get_json(force=True, silent=True) or {}
            raw_value = data.get("value", "").strip()
            entry_type = data.get("entry_type", "domain")
            reason = data.get("reason", "")[:255]

            if entry_type not in ("domain", "ip"):
                return jsonify({"error": "entry_type must be 'domain' or 'ip'"}), 400

            if entry_type == "domain":
                value = validators.normalize_domain(raw_value)
            else:
                value = raw_value.strip()

            if not validators.is_valid_block_value(value, entry_type):
                return jsonify({"error": f"'{raw_value}' doesn't look like a valid {entry_type}"}), 400

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

    @app.route("/api/most-used")
    @login_required
    def api_most_used():
        db.session.expire_all()
        from sqlalchemy import func
        top = (
            db.session.query(ActivityLog.domain, func.count(ActivityLog.id).label("hits"))
            .filter(ActivityLog.domain.isnot(None), ActivityLog.domain != "")
            .group_by(ActivityLog.domain)
            .order_by(func.count(ActivityLog.id).desc())
            .limit(6)
            .all()
        )
        return jsonify([{"domain": row[0], "hits": row[1]} for row in top])

    @app.route("/api/audit-log")
    @login_required
    def api_audit_log():
        db.session.expire_all()
        limit = request.args.get("limit", default=50, type=int)
        entries = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(limit).all()
        return jsonify([e.to_dict() for e in entries])

    @app.route("/api/stats")
    @login_required
    def api_stats():
        db.session.expire_all()
        devices = Device.query.all()
        connected_now = sum(1 for d in devices if d.to_dict()["connected"])
        return jsonify({
            "known_devices": len(devices),
            "connected_now": connected_now,
            "active_block_rules": BlockedEntry.query.count(),
            "blocked_requests": ActivityLog.query.filter_by(status="blocked").count(),
        })


import platform
import subprocess
import sys
import os


def free_port(port: int):
    """Ensure port is available on Linux by stopping stale GuardSpot/Flask instances."""
    if platform.system() == "Linux":
        curr_pid = os.getpid()
        try:
            res = subprocess.run(["fuser", f"{port}/tcp"], capture_output=True, text=True)
            pids = [int(p.strip()) for p in res.stdout.strip().split() if p.strip().isdigit()]
            for p in pids:
                if p != curr_pid:
                    subprocess.run(["kill", "-9", str(p)], check=False)
        except Exception:
            pass
        try:
            out = subprocess.check_output(f"lsof -ti:{port}", shell=True, text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                if line.strip().isdigit():
                    p = int(line.strip())
                    if p != curr_pid:
                        subprocess.run(["kill", "-9", str(p)], check=False)
        except Exception:
            pass
        import time
        time.sleep(0.5)


def auto_start_sniffer():
    """Automatically starts the background packet sniffer so you only ever have to run app.py."""
    if not config.IS_PI and not config.LOCAL_CAPTURE:
        print("[GuardSpot] Laptop mode: waiting for the Raspberry Pi SSH connection; local sniffer disabled.")
        return

    base_dir = os.path.dirname(os.path.abspath(__file__))
    sniffer_path = os.path.join(base_dir, "sniffer.py")

    if platform.system() == "Linux":
        try:
            res = subprocess.run(["pgrep", "-f", "sniffer.py"], capture_output=True, text=True)
            pids = [p for p in res.stdout.strip().split() if p and int(p) != os.getpid()]
            if not pids:
                cmd = ["sudo", sys.executable, "-u", sniffer_path] if os.geteuid() != 0 else [sys.executable, "-u", sniffer_path]
                log_path = os.path.join(base_dir, "sniffer.log")
                log_fh = open(log_path, "a", buffering=1)
                env = os.environ.copy()
                env["PYTHONUNBUFFERED"] = "1"
                subprocess.Popen(cmd, stdout=log_fh, stderr=log_fh, env=env, start_new_session=True)
                print(f"[GuardSpot] Background packet sniffer started on Linux/Pi (logging to {log_path}).")
        except Exception as e:
            print(f"[GuardSpot] Notice: Could not auto-start sniffer: {e}")

    elif platform.system() == "Windows":
        try:
            ps_cmd = 'powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \\"CommandLine LIKE \'%sniffer.py%\'\\" | Select-Object -ExpandProperty ProcessId"'
            out = subprocess.check_output(ps_cmd, shell=True).decode(errors="ignore")
            pids = [p.strip() for p in out.splitlines() if p.strip().isdigit() and int(p.strip()) != os.getpid()]
            if not pids:
                log_path = os.path.join(base_dir, "sniffer.log")
                log_fh = open(log_path, "a", buffering=1)
                env = os.environ.copy()
                env["PYTHONUNBUFFERED"] = "1"
                subprocess.Popen([sys.executable, "-u", sniffer_path], stdout=log_fh, stderr=log_fh, env=env, creationflags=subprocess.CREATE_NO_WINDOW)
                print(f"[GuardSpot] Background packet sniffer started on Windows (logging to {log_path}).")
        except Exception as e:
            print(f"[GuardSpot] Notice: Could not auto-start sniffer on Windows: {e}")


if __name__ == "__main__":
    if platform.system() == "Linux" and hasattr(os, "geteuid") and os.geteuid() != 0:
        print("\n" + "=" * 65)
        print(" [!] NOTICE: For full gateway firewall functionality (iptables drop,")
        print("     DNS redirection, Wi-Fi kick), run GuardSpot as root:")
        print("         sudo python3 app.py")
        print("=" * 65 + "\n")

    free_port(config.PORT)
    blocklist_module.init_gateway_firewall()
    auto_start_sniffer()

    app = create_app()
    with app.app_context():
        try:
            entries = BlockedEntry.query.all()
            for entry in entries:
                blocklist_module.enforce_block(entry.value, entry.entry_type)
            devices = Device.query.filter_by(is_blocked=True).all()
            for dev in devices:
                blocklist_module.block_device(dev.ip_address, dev.mac_address)
            print(f"[GuardSpot Firewall] Active: {len(entries)} blocklist rules & {len(devices)} blocked devices enforced.")
        except Exception as e:
            print(f"[GuardSpot Firewall] Sync notice: {e}")

    debug_mode = config.__dict__.get("DEBUG", False)
    app.run(host=config.HOST, port=config.PORT, debug=debug_mode)
