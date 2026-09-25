"""
config.py
---------
Central configuration for GuardSpot.
Edit these values for your Raspberry Pi setup before running anything.
"""

import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

CAPTURE_INTERFACE = 12
CAPTURE_FILTER = "udp port 53"

SQLALCHEMY_DATABASE_URI = f"sqlite:///{os.path.join(BASE_DIR, 'guardspot.db')}"

BLOCK_METHOD = "dns"
DNSMASQ_BLOCKLIST_FILE = "/etc/dnsmasq.d/guardspot_blocklist.conf"

SECRET_KEY = os.environ.get("GUARDSPOT_SECRET_KEY", "change-this-in-production")
ADMIN_USERNAME = os.environ.get("GUARDSPOT_ADMIN", "admin")
ADMIN_PASSWORD = os.environ.get("GUARDSPOT_ADMIN_PASSWORD", "change-this-password")

# Bind to loopback only. Access now happens exclusively through an SSH
# tunnel — SSH is the real authentication gate, so the dashboard itself
# isn't exposed directly on the network anymore.
HOST = "127.0.0.1"
PORT = 5000

# ---- SSH connector (when this project runs on YOUR LAPTOP as the
# login/connector, instead of on the Pi as the real dashboard) ----
TUNNEL_LOCAL_PORT = int(os.environ.get("GUARDSPOT_FORWARD_PORT", 5050))

# Only the Pi-hosted instance should ever auto-trust a loopback connection
# (that is how the SSH tunnel authenticates). On your laptop this MUST stay
# False, or your own browser hitting its own localhost skips the SSH
# login screen entirely - set GUARDSPOT_IS_PI=true only on the Pi.
IS_PI = os.environ.get("GUARDSPOT_IS_PI", "false").lower() == "true"
