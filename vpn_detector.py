"""
vpn_detector.py
---------------
VPN, Proxy, and Encrypted DNS Bypass Detection Engine for GuardSpot.

Monitors:
1. Standard VPN handshake ports (WireGuard, OpenVPN, IPsec/IKEv2, PPTP, L2TP).
2. Private DNS / DNS-over-TLS (DoT port 853) used by Android/iOS to bypass local DNS.
3. Domain lookups belonging to commercial VPN providers (NordVPN, ExpressVPN,
   ProtonVPN, Cloudflare WARP, Surfshark, TurboVPN, etc.).
"""

import validators

# Known VPN & encrypted tunnel handshake ports
VPN_PORTS = {
    51820: "WireGuard VPN",
    51821: "WireGuard VPN",
    1194: "OpenVPN",
    500: "IPsec / IKEv2",
    4500: "IPsec NAT-Traversal",
    853: "DNS-over-TLS (Private DNS)",
    1723: "PPTP VPN",
    1701: "L2TP VPN",
}

# Known VPN service provider domains and DNS-bypass resolvers
VPN_DOMAINS = {
    # Cloudflare WARP / 1.1.1.1
    "cloudflarewarp.com": "Cloudflare WARP",
    "warp.plus": "Cloudflare WARP",
    "cloudflare-dns.com": "Cloudflare Encrypted DNS",
    # NordVPN
    "nordvpn.com": "NordVPN",
    "nordconnect.com": "NordVPN",
    "nordvpn.net": "NordVPN",
    # ExpressVPN
    "expressvpn.com": "ExpressVPN",
    "expressvpn.net": "ExpressVPN",
    "expvpn.com": "ExpressVPN",
    # ProtonVPN
    "protonvpn.com": "ProtonVPN",
    "protonvpn.net": "ProtonVPN",
    # Surfshark
    "surfshark.com": "Surfshark",
    "surfsharkdns.com": "Surfshark",
    # CyberGhost
    "cyberghostvpn.com": "CyberGhost VPN",
    "cg-vpn.com": "CyberGhost VPN",
    # Windscribe
    "windscribe.com": "Windscribe VPN",
    # TurboVPN
    "turbovpn.co": "Turbo VPN",
    "turbovpn.org": "Turbo VPN",
    "turbovpn.net": "Turbo VPN",
    # TunnelBear
    "tunnelbear.com": "TunnelBear",
    # Hotspot Shield
    "hotspotshield.com": "Hotspot Shield",
    "anchorfree.com": "AnchorFree / Hotspot Shield",
    # Mullvad
    "mullvad.net": "Mullvad VPN",
    # Private Internet Access
    "privateinternetaccess.com": "PIA VPN",
    # IPVanish
    "ipvanish.com": "IPVanish",
    # PureVPN
    "purevpn.com": "PureVPN",
    # AdGuard VPN & Private DNS
    "adguard-vpn.com": "AdGuard VPN",
    "dns.adguard.com": "AdGuard Private DNS",
    # Psiphon
    "psiphon.ca": "Psiphon VPN",
    "psiphon3.com": "Psiphon VPN",
    # Tor Project
    "torproject.org": "Tor / Onion Network",
    "bridges.torproject.org": "Tor Bridge",
    # Google & Quad9 DoH/DoT
    "dns.google": "Google Private DNS",
    "dns.quad9.net": "Quad9 Private DNS",
}


def detect_vpn_port(port: int) -> str:
    """Return VPN name if the given port is a known VPN protocol port."""
    return VPN_PORTS.get(port)


def detect_vpn_domain(domain: str) -> str:
    """
    Check if domain or any parent domain belongs to a VPN service.
    Returns the VPN provider name (e.g. 'NordVPN') or None.
    """
    if not domain:
        return None

    clean = validators.normalize_domain(domain)
    parts = clean.split(".")

    for i in range(len(parts) - 1):
        parent = ".".join(parts[i:])
        if parent in VPN_DOMAINS:
            return VPN_DOMAINS[parent]

    return None


def get_capture_filter() -> str:
    """
    Generates a BPF packet capture filter that monitors DNS (UDP 53)
    plus all common VPN handshake ports.
    """
    port_clauses = [
        "udp port 53",
        "udp port 51820",
        "udp port 1194",
        "tcp port 1194",
        "udp port 500",
        "udp port 4500",
        "tcp port 853",
        "tcp port 1723",
    ]
    return " or ".join(port_clauses)
