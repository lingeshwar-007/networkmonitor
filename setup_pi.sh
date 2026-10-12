#!/bin/bash
# setup_pi.sh
# Run once on a fresh Raspberry Pi OS install, from inside the project folder:
#   chmod +x setup_pi.sh && ./setup_pi.sh
# (the repository is flat: app.py, requirements.txt and this script live together)

set -e
cd "$(dirname "$0")"

echo "== Updating system =="
sudo apt update && sudo apt upgrade -y

echo "== Installing OS packages =="
sudo apt install -y python3 python3-pip python3-venv \
                     libpcap-dev tcpdump \
                     dnsmasq \
                     hostapd \
                     iptables \
                     conntrack \
                     iw

echo "== Preparing hostapd deny file =="
sudo mkdir -p /etc/hostapd
sudo touch /etc/hostapd/hostapd.deny
sudo chmod 644 /etc/hostapd/hostapd.deny

echo "== Preparing GuardSpot firewall files =="
sudo mkdir -p /etc/guardspot /etc/dnsmasq.d
sudo touch /etc/guardspot/blocked_domains.servers
sudo chmod 644 /etc/guardspot/blocked_domains.servers
# dnsmasq re-reads this file on SIGHUP, so website blocks apply instantly.
echo "servers-file=/etc/guardspot/blocked_domains.servers" | sudo tee /etc/dnsmasq.d/guardspot.conf >/dev/null
if [ -d /etc/NetworkManager/dnsmasq-shared.d ]; then
  echo "servers-file=/etc/guardspot/blocked_domains.servers" | sudo tee /etc/NetworkManager/dnsmasq-shared.d/guardspot.conf >/dev/null
fi

echo "== Enabling IP forwarding + conntrack accounting permanently =="
sudo tee /etc/sysctl.d/99-guardspot.conf >/dev/null <<'SYSCTL'
net.ipv4.ip_forward=1
net.netfilter.nf_conntrack_acct=1
SYSCTL
sudo sysctl --system >/dev/null || true

echo "== Restarting dnsmasq to load the GuardSpot include =="
sudo systemctl enable dnsmasq >/dev/null 2>&1 || true
sudo systemctl restart dnsmasq || echo "   (dnsmasq not started yet - fine if NetworkManager runs the hotspot)"

echo "== Creating Python virtual environment =="
python3 -m venv venv
source venv/bin/activate

echo "== Installing Python dependencies =="
pip install --upgrade pip
pip install -r requirements.txt

echo "== Done =="
echo "Next steps:"
echo "1. Make the Pi the Wi-Fi hotspot (hostapd + dnsmasq, see pi-config/ and README.md)."
echo "   If you use a NetworkManager hotspot, reconnect it once so its dnsmasq loads the include:"
echo "     nmcli connection down <hotspot-name> && nmcli connection up <hotspot-name>"
echo "2. Run GuardSpot as root (it manages the firewall):  sudo ./venv/bin/python3 app.py"
echo "   or install the systemd unit from pi-config/guardspot-web.service"
echo "3. Open the dashboard. The banner at the top turns green when every firewall layer is active"
echo "   and tells you exactly what is missing when it is not."
