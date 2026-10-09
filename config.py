"""
config.py
---------
Central configuration for GuardSpot.
Supports both Windows Mobile Hotspot and Raspberry Pi (Wi-Fi hotspot or Ethernet).
"""

import os
import platform

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


def _check_is_pi():
    """Detect if running on a real Raspberry Pi or explicitly configured for Pi mode."""
    env_pi = os.environ.get("GUARDSPOT_IS_PI")
    if env_pi is not None:
        return env_pi.lower() == "true"

    if platform.system() == "Linux":
        # Check if running inside WSL on a Windows laptop
        try:
            with open("/proc/version", "r") as f:
                ver = f.read().lower()
                if "microsoft" in ver or "wsl" in ver:
                    return False  # WSL on Windows
        except Exception:
            pass

        # 1. Check device-tree paths
        for dt_path in ["/proc/device-tree/model", "/sys/firmware/devicetree/base/model"]:
            try:
                with open(dt_path, "r", errors="ignore") as f:
                    if "raspberry pi" in f.read().lower():
                        return True
            except Exception:
                pass

        # 2. Check /proc/cpuinfo
        try:
            with open("/proc/cpuinfo", "r", errors="ignore") as f:
                cpuinfo = f.read().lower()
                if "raspberry pi" in cpuinfo or "bcm27" in cpuinfo or "bcm28" in cpuinfo:
                    return True
        except Exception:
            pass

        # 3. Check for Pi OS release / hardware
        try:
            with open("/etc/os-release", "r", errors="ignore") as f:
                os_rel = f.read().lower()
                if "raspbian" in os_rel or "raspberry" in os_rel:
                    return True
        except Exception:
            pass

        # 4. If on Linux (not WSL) and hostapd/dnsmasq exists, it's the Pi AP
        if os.path.exists("/etc/hostapd") or os.path.exists("/etc/dnsmasq.conf") or os.path.exists("/sys/class/net/wlan0"):
            return True

        return True  # Native Linux non-WSL is treated as Pi/Linux mode

    return False


# Mode detection: Pi vs Windows
IS_PI = _check_is_pi()

# Network capture interface:
# On Windows Mobile Hotspot: defaults to the virtual adapter IP "192.168.137.1"
# On Raspberry Pi: defaults to "wlan0" (Wi-Fi hotspot) or "eth0" (Ethernet)
import vpn_detector

DEFAULT_IFACE = "wlan0" if IS_PI else "192.168.137.1"
CAPTURE_INTERFACE = os.environ.get("GUARDSPOT_IFACE", DEFAULT_IFACE)
CAPTURE_FILTER = os.environ.get("GUARDSPOT_FILTER", vpn_detector.get_capture_filter())


SQLALCHEMY_DATABASE_URI = f"sqlite:///{os.path.join(BASE_DIR, 'guardspot.db')}"

BLOCK_METHOD = "dns"
DNSMASQ_BLOCKLIST_FILE = "/etc/dnsmasq.d/guardspot_blocklist.conf"

SECRET_KEY = os.environ.get("GUARDSPOT_SECRET_KEY", "change-this-in-production")
ADMIN_USERNAME = os.environ.get("GUARDSPOT_ADMIN", "admin")
ADMIN_PASSWORD = os.environ.get("GUARDSPOT_ADMIN_PASSWORD", "change-this-password")

# Bind address and port
HOST = os.environ.get("GUARDSPOT_HOST", "127.0.0.1")
PORT = int(os.environ.get("GUARDSPOT_PORT", 5000))

# SSH connector settings (for remote control of Raspberry Pi)
TUNNEL_LOCAL_PORT = int(os.environ.get("GUARDSPOT_FORWARD_PORT", 5050))
