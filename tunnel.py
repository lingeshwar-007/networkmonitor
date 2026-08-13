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


def connect_ssh(pi_ip, ssh_username, password=None, key_path=None, ssh_port=22):
    """Opens an SSH connection to the Pi. Raises on failure."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    if key_path:
        pkey = paramiko.RSAKey.from_private_key_file(key_path)
        client.connect(pi_ip, port=ssh_port, username=ssh_username, pkey=pkey, timeout=10)
    else:
        client.connect(pi_ip, port=ssh_port, username=ssh_username, password=password, timeout=10)

    return client


def start_forward(local_port, remote_host, remote_port, transport):
    """Starts the local forwarding server in a background thread."""
    handler = _make_handler(remote_host, remote_port, transport)
    server = ForwardServer(("127.0.0.1", local_port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server
