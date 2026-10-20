"""
Best-effort classification of DNS domains into applications or services.

This does not identify the exact browser/process on the client device. It maps
observed domains to the service family that commonly owns them.
"""

from validators import normalize_domain

# Longer/more-specific domains are checked before broad parent domains.
SERVICE_RULES = {
    # Social and messaging
    "cdninstagram.com": "Instagram",
    "instagram.com": "Instagram",
    "ig.me": "Instagram",
    "graph.instagram.com": "Instagram",
    "facebook.com": "Facebook",
    "fbcdn.net": "Facebook",
    "facebook.net": "Facebook",
    "messenger.com": "Messenger",
    "whatsapp.net": "WhatsApp",
    "whatsapp.com": "WhatsApp",
    "wa.me": "WhatsApp",
    "threads.net": "Threads",

    # Video, music, and entertainment
    "googlevideo.com": "YouTube",
    "ytimg.com": "YouTube",
    "youtube.com": "YouTube",
    "youtu.be": "YouTube",
    "youtubei.googleapis.com": "YouTube",
    "netflix.com": "Netflix",
    "nflxvideo.net": "Netflix",
    "nflximg.net": "Netflix",
    "tiktok.com": "TikTok",
    "tiktokcdn.com": "TikTok",
    "tiktokv.com": "TikTok",
    "spotify.com": "Spotify",
    "scdn.co": "Spotify",
    "twitch.tv": "Twitch",
    "discord.com": "Discord",
    "discordapp.com": "Discord",

    # Google and Android platform services
    "play.googleapis.com": "Google Play Services",
    "play-fe.googleapis.com": "Google Play Services",
    "android.clients.google.com": "Google Play Services",
    "play-lh.googleusercontent.com": "Google Play Services",
    "gstatic.com": "Google Services",
    "googleapis.com": "Google Services",
    "google.com": "Google Services",
    "connectivitycheck.gstatic.com": "Android Connectivity Check",
    "backup.googleapis.com": "Android Backup",
    "time.android.com": "Android Time Sync",

    # Device-vendor background services
    "heytapmobile.com": "Android/OPPO System",
    "heytapdl.com": "Android/OPPO System",
    "allawnos.com": "Android/OPPO System",

    # Network/background services
    "ntp.org": "Time Synchronization",
    "pool.ntp.org": "Time Synchronization",
    "dns.google": "Google Private DNS",
    "dns.quad9.net": "Quad9 Private DNS",
}


def classify_domain(domain: str) -> str:
    """Return a service label for a domain, or 'Other/Unknown'."""
    clean = normalize_domain(domain)
    if not clean:
        return "Other/Unknown"

    labels = clean.split(".")
    for index in range(len(labels)):
        candidate = ".".join(labels[index:])
        if candidate in SERVICE_RULES:
            return SERVICE_RULES[candidate]

    return "Other/Unknown"
