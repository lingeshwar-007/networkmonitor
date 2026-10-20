#!/bin/bash
# setup_pi.sh
# Run once on a fresh Raspberry Pi OS install (as a user with sudo).
# Place this file next to the networkmonitor/ folder, then:
#   chmod +x setup_pi.sh && ./setup_pi.sh

set -e

echo "== Updating system =="
sudo apt update && sudo apt upgrade -y

echo "== Installing OS packages =="
sudo apt install -y python3 python3-pip python3-venv \
                     libpcap-dev tcpdump \
                     dnsmasq \
                     hostapd \
                     avahi-daemon \
                     iptables \
                     conntrack \
                     iw

echo "== Setting up hostapd deny files =="
sudo mkdir -p /etc/hostapd
sudo touch /etc/hostapd/hostapd.deny
sudo chmod 666 /etc/hostapd/hostapd.deny

echo "== Creating Python virtual environment =="
python3 -m venv venv
source venv/bin/activate

echo "== Installing Python dependencies =="
pip install --upgrade pip
pip install -r networkmonitor/requirements.txt

echo "== Done =="
echo "Next steps:"
echo "1. Set a stable hostname: sudo hostnamectl set-hostname guardspot"
echo "2. Enable mDNS: sudo systemctl enable --now avahi-daemon"
echo "3. Configure hostapd + dnsmasq so the Pi acts as the Wi-Fi hotspot (see README.md)."
echo "4. Edit networkmonitor/config.py -> CAPTURE_INTERFACE to match your hotspot interface (usually wlan0)."
echo "5. cd networkmonitor"
echo "6. Run the sniffer:   sudo ../venv/bin/python3 sniffer.py"
echo "7. Run the dashboard: ../venv/bin/python3 app.py"
