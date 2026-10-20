"""
tunnel.py
---------
Opens an SSH connection to the Pi and forwards a local port to the Pi's
GuardSpot dashboard (which only listens on the Pi's own loopback address).
"""

import select
import socketserver
import threading
import paramiko


class ForwardServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def _make_handler(remote_host, remote_port, transport):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                chan = transport.open_channel(
                    "direct-tcpip",
                    (remote_host, remote_port),
                    self.request.getpeername(),
                )
            except Exception:
                return
            if chan is None:
                return

            while True:
                r, _, _ = select.select([self.request, chan], [], [])
                if self.request in r:
                    data = self.request.recv(4096)
                    if len(data) == 0:
                        break
                    chan.send(data)
                if chan in r:
                    data = chan.recv(4096)
                    if len(data) == 0:
                        break
                    self.request.send(data)

            chan.close()
            self.request.close()

    return Handler


import socket
import re
import subprocess
import os
import config


def resolve_pi_host(host_or_ip: str = "guardspot") -> str:
    """Find a Pi by hostname first, falling back to a discovered LAN IP."""
    target = (host_or_ip or config.PI_HOSTNAME).strip()

    # Keep hostnames as hostnames so SSH host-key verification matches the
    # hostname stored in known_hosts. DNS/mDNS handles the changing address.
    if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", target):
        candidates = [target]
        if not target.endswith(".local"):
            candidates.append(f"{target}.local")
        for candidate in candidates:
            try:
                socket.gethostbyname(candidate)
                return candidate
            except Exception:
                pass

    # 1. Direct DNS / NetBIOS / mDNS resolution, including standard names.
    for candidate in ("guardspot.local", "guardspot", "raspberrypi.local", "raspberrypi"):
        try:
            socket.gethostbyname(candidate)
            return candidate
        except Exception:
            pass

    # 2. Check ARP table for LAN IPs that respond on SSH port 22.
    try:
        arp_output = subprocess.check_output("arp -a", shell=True).decode(errors="ignore")
        lan_ips = re.findall(r"(\b192\.168\.\d+\.\d+\b|\b10\.\d+\.\d+\.\d+\b)", arp_output)
        for ip in set(lan_ips):
            if ip.endswith(".255") or ip.endswith(".1"):
                continue
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.4)
                if s.connect_ex((ip, 22)) == 0:
                    s.close()
                    return ip
                s.close()
            except Exception:
                pass
    except Exception:
        pass

    return target


import time


def ensure_remote_services(client):
    """Ensure both sniffer.py and app.py are actively running on the Raspberry Pi."""
    remote_dir = config.REMOTE_PROJECT_DIR
    python_bin = f"{remote_dir}/venv/bin/python3"
    # Fall back to the system interpreter when the Pi project has no venv.
    python_cmd = f"test -x {python_bin} && echo {python_bin} || echo python3"
    _, stdout, _ = client.exec_command(python_cmd)
    python_exec = stdout.read().decode(errors="ignore").strip() or "python3"

    # 1. Ensure sniffer.py is running on the Pi
    try:
        _, stdout, _ = client.exec_command("pgrep -f sniffer.py")
        if not stdout.read().strip():
            client.exec_command(
                f"cd {remote_dir} && nohup sudo {python_exec} sniffer.py > /tmp/guardspot-sniffer.log 2>&1 &"
            )
            print("[GuardSpot] Remote packet sniffer started on Raspberry Pi.")
    except Exception as e:
        print(f"[GuardSpot] Notice: Could not start remote sniffer: {e}")

    # 2. Ensure app.py is running on the Pi (for the SSH tunnel port 5050 -> 5000)
    try:
        _, stdout, _ = client.exec_command("pgrep -f 'python3 app.py'")
        if not stdout.read().strip():
            client.exec_command(
                f"cd {remote_dir} && nohup env GUARDSPOT_IS_PI=true GUARDSPOT_HOST=127.0.0.1 {python_exec} app.py > /tmp/guardspot-app.log 2>&1 &"
            )
            print("[GuardSpot] Remote web dashboard started on Raspberry Pi.")
            time.sleep(2)  # Give Flask 2 seconds to bind port 5000
    except Exception as e:
        print(f"[GuardSpot] Notice: Could not start remote app: {e}")


def connect_ssh(pi_ip, ssh_username, password=None, key_path=None, ssh_port=22):
    """Opens an SSH connection to the Pi (resolving dynamic DHCP hostname). Raises on failure."""
    resolved_host = resolve_pi_host(pi_ip)

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    # Secure default: reject unknown host keys. Set GUARDSPOT_SSH_ALLOW_UNKNOWN_HOST=1
    # only for temporary development when the Pi key is not yet in ~/.ssh/known_hosts.
    if os.environ.get("GUARDSPOT_SSH_ALLOW_UNKNOWN_HOST", "").lower() in {"1", "true", "yes"}:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

    if key_path:
        pkey = paramiko.RSAKey.from_private_key_file(key_path)
        client.connect(resolved_host, port=ssh_port, username=ssh_username, pkey=pkey, timeout=10)
    else:
        client.connect(resolved_host, port=ssh_port, username=ssh_username, password=password, timeout=10)

    # Automatically ensure packet sniffer is capturing on the Pi
    ensure_remote_services(client)

    return client


def start_forward(local_port, remote_host, remote_port, transport):
    """Starts the local forwarding server in a background thread."""
    handler = _make_handler(remote_host, remote_port, transport)
    server = ForwardServer(("127.0.0.1", local_port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server
