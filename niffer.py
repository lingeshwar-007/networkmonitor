warning: in the working copy of 'config.py', LF will be replaced by CRLF the next time Git touches it
warning: in the working copy of 'sniffer.py', LF will be replaced by CRLF the next time Git touches it
[1mdiff --git a/config.py b/config.py[m
[1mindex 2e6ba9f..b2b23e2 100644[m
[1m--- a/config.py[m
[1m+++ b/config.py[m
[36m@@ -9,7 +9,7 @@[m [mimport os[m
 [m
 BASE_DIR = os.path.abspath(os.path.dirname(__file__))[m
 [m
[31m-CAPTURE_INTERFACE = "wlan0"[m
[32m+[m[32mCAPTURE_INTERFACE = 12[m
 CAPTURE_FILTER = "udp port 53"[m
 [m
 SQLALCHEMY_DATABASE_URI = f"sqlite:///{os.path.join(BASE_DIR, 'guardspot.db')}"[m
[1mdiff --git a/sniffer.py b/sniffer.py[m
[1mindex c4c034f..df85f25 100644[m
[1m--- a/sniffer.py[m
[1m+++ b/sniffer.py[m
[36m@@ -1,18 +1,20 @@[m
[31m-"""[m
[32m+[m[32m﻿"""[m
 sniffer.py[m
 ----------[m
[31m-Runs continuously on the Raspberry Pi. Captures DNS query packets on the[m
[32m+[m[32mRuns continuously on the network host. Captures DNS query packets on the[m
 network interface, works out which device asked for which domain, checks[m
 the domain against the blocklist, and writes an ActivityLog row.[m
[32m+[m[32mAlso watches DNS *responses* so blocked domains can be firewalled by IP[m
[32m+[m[32m(needed on Windows, which has no dnsmasq to refuse resolution outright).[m
 [m
[31m-This must run as root (packet capture needs raw socket access):[m
[31m-    sudo python3 sniffer.py[m
[32m+[m[32mThis must run elevated (raw socket access + firewall changes):[m
[32m+[m[32m    python sniffer.py   (as Administrator / with sudo)[m
 [m
 It shares the same Flask app + DB, so activity appears on the dashboard live.[m
 """[m
 [m
 import datetime[m
[31m-from scapy.all import sniff, DNS, DNSQR, IP[m
[32m+[m[32mfrom scapy.all import sniff, DNS, DNSQR, DNSRR, IP[m
 [m
 from app import create_app[m
 from models import db, Device, ActivityLog[m
[36m@@ -35,27 +37,29 @@[m [mdef get_or_create_device(ip_address):[m
 [m
 [m
 def handle_packet(pkt):[m
[31m-    # Only interested in outgoing DNS *queries* (qr=0), not the responses.[m
[31m-    if not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR):[m
[31m-        return[m
[31m-    if pkt[DNS].qr != 0:[m
[31m-        return[m
[31m-    if not pkt.haslayer(IP):[m
[32m+[m[32m    if not pkt.haslayer(DNS) or not pkt.haslayer(IP):[m
         return[m
[32m+[m[32m    if pkt[DNS].qr == 0:[m
[32m+[m[32m        handle_query(pkt)[m
[32m+[m[32m    else:[m
[32m+[m[32m        handle_response(pkt)[m
 [m
[32m+[m
[32m+[m[32mdef handle_query(pkt):[m
[32m+[m[32m    if not pkt.haslayer(DNSQR):[m
[32m+[m[32m        return[m
     src_ip = pkt[IP].src[m
     domain = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")[m
 [m
     with app.app_context():[m
         device = get_or_create_device(src_ip)[m
[31m-[m
         blocked = blocklist.is_blocked(domain)[m
         status = "blocked" if blocked else "allowed"[m
 [m
         log_entry = ActivityLog([m
             device_id=device.id,[m
             domain=domain,[m
[31m-            resolved_ip=None,  # filled in later if we see the DNS response[m
[32m+[m[32m            resolved_ip=None,[m
             status=status,[m
         )[m
         db.session.add(log_entry)[m
[36m@@ -64,6 +68,27 @@[m [mdef handle_packet(pkt):[m
         print(f"[{status.upper()}] {src_ip} -> {domain}")[m
 [m
 [m
[32m+[m[32mdef handle_response(pkt):[m
[32m+[m[32m    """Windows-only: watch DNS responses to learn which IP a blocked[m
[32m+[m[32m    domain resolved to, then ask blocklist.py to firewall that IP."""[m
[32m+[m[32m    if not pkt.haslayer(DNSRR):[m
[32m+[m[32m        return[m
[32m+[m[32m    try:[m
[32m+[m[32m        domain = pkt[DNS].qd.qname.decode(errors="ignore").rstrip(".")[m
[32m+[m[32m    except (AttributeError, IndexError):[m
[32m+[m[32m        return[m
[32m+[m
[32m+[m[32m    with app.app_context():[m
[32m+[m[32m        if not blocklist.is_blocked(domain):[m
[32m+[m[32m            return[m
[32m+[m[32m        for i in range(pkt[DNS].ancount):[m
[32m+[m[32m            rr = pkt[DNS].an[i][m
[32m+[m[32m            if rr.type == 1:  # A record[m
[32m+[m[32m                resolved_ip = rr.rdata[m
[32m+[m[32m                blocklist.enforce_domain_ip(domain, resolved_ip)[m
[32m+[m[32m                print(f"[FIREWALL] {domain} -> {resolved_ip} blocked")[m
[32m+[m
[32m+[m
 def main():[m
     print(f"GuardSpot sniffer starting on interface: {config.CAPTURE_INTERFACE}")[m
     print(f"Filter: {config.CAPTURE_FILTER}")[m
