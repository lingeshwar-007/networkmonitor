# GuardSpot — Raspberry Pi Network Monitoring System

A home network monitoring tool. The Raspberry Pi sits as (or alongside) the
Wi-Fi access point, watches every device's DNS requests, logs them, and lets
the **admin only** (you) view activity and block domains/IPs from a web
dashboard. Regular users never log in — they're just the devices being
observed.

---

## 1. What "checking if a domain/IP is usable" actually means

There's no way to ask the internet "is this blocked?" — blocking is a rule
*you* enforce locally. So "usable" here means: **not present in your own
blocklist table**.

Flow for every DNS request:

1. Device asks the Pi's DNS resolver to resolve `somesite.com`.
2. GuardSpot checks `somesite.com` against the `BlockedEntry` table.
3. **Not in the list** → request is allowed to resolve normally → logged as `allowed`.
4. **In the list** → the resolver (dnsmasq) returns `0.0.0.0` instead of the
   real IP, so the device's connection attempt fails → logged as `blocked`.

So "is it usable" = "is it absent from the admin's blocklist" — and the
actual denial happens at the DNS layer (or firewall layer if you block by IP
with iptables), not inside the Flask app itself. Flask/the sniffer just
decide *whether* to apply the rule and record what happened.

---

## 2. Software you need on the Raspberry Pi

| Purpose | Software |
|---|---|
| OS | Raspberry Pi OS (Bookworm, Lite is fine — no desktop needed) |
| Language/runtime | Python 3.11+, pip, venv |
| Packet capture | `scapy` (Python), `libpcap-dev`, `tcpdump` (for testing) |
| Acting as the Wi-Fi hotspot | `hostapd` (creates the Wi-Fi network) + `dnsmasq` (DHCP + DNS server) |
| Enforcing blocks | `dnsmasq` (domain blocking) and/or `iptables` (IP blocking) |
| Web backend | `Flask`, `Flask-SQLAlchemy` |
| Database | SQLite (built into Python — no separate install) |
| Process management (optional, recommended) | `systemd` service files so `app.py` and `sniffer.py` auto-start on boot |

All of this is installed by `setup_pi.sh` except the hostapd/dnsmasq
*configuration* (making the Pi actually broadcast Wi-Fi), which is
network-specific — the official Raspberry Pi hotspot guide covers that part:
`https://www.raspberrypi.com/documentation/computers/configuration.html#setting-up-a-routed-wireless-access-point`

You do **not** need Npcap — that's the Windows equivalent of libpcap; on
Linux/Raspberry Pi OS, `libpcap` (installed via apt) is what scapy uses.

---

## 3. Full workflow (what happens end-to-end)

```
[Phone/Laptop] --DNS query--> [Pi: dnsmasq]
                                   |
                                   | (dnsmasq is the DNS server the whole
                                   |  network uses, because the Pi is the
                                   |  hotspot/router)
                                   v
                         resolves normally, OR
                         returns 0.0.0.0 if domain is in blocklist
                                   |
        (meanwhile, on the same interface)
                                   |
                                   v
                         [sniffer.py, running as root]
                         watches all UDP port 53 traffic,
                         sees who (source IP) asked for what (domain),
                         checks BlockedEntry table,
                         writes a row to ActivityLog
                                   |
                                   v
                         [guardspot.db  (SQLite)]
                                   |
                                   v
                         [app.py — Flask web server]
                         reads the DB, serves the admin
                         dashboard + JSON API
                                   |
                                   v
                    [You, the admin, on your laptop's browser]
                    log in -> see live device list, activity feed,
                    add/remove blocklist entries
```

Two Python processes run simultaneously and share the same database file:

- **`sniffer.py`** — passive observer + logger. Needs root (raw packet
  capture). Runs forever in the background.
- **`app.py`** — the website. No special privileges needed. Also runs
  forever (or on-demand), serving the dashboard on port 5000.

They never call each other directly — they communicate only through
`guardspot.db`.

---

## 4. What happens when you run `app.py`

```
python3 app.py
```

1. `create_app()` builds the Flask app and points it at `guardspot.db`
   (via `config.py`'s `SQLALCHEMY_DATABASE_URI`).
2. `db.create_all()` creates the three tables (`devices`, `activity_log`,
   `blocked_entries`) if they don't exist yet — no manual DB setup needed.
3. `register_routes(app)` wires up:
   - `/login`, `/logout` — the single admin account (from `config.py`).
   - `/` — the dashboard page (`templates/dashboard.html`).
   - `/api/devices`, `/api/activity`, `/api/blocklist`, `/api/stats` — JSON
     endpoints the dashboard's JavaScript polls every few seconds.
4. `app.run(...)` starts the built-in web server on `0.0.0.0:5000`, so it's
   reachable from any device on your LAN at `http://<pi-ip-address>:5000`.

It does **not** touch the network interface or capture any packets — it's
purely a database viewer + editor with a login wall.

## What happens when you run `sniffer.py`

```
sudo python3 sniffer.py
```

1. Imports `create_app()` from `app.py` so it can use the *same* database
   models and app context (this is why it must be run from the same folder).
2. `sniff(iface=..., filter="udp port 53", prn=handle_packet)` starts
   listening on the configured interface using scapy — this requires root.
3. For every DNS query packet seen:
   - Pulls out the source IP (`pkt[IP].src`) — the device that asked.
   - Pulls out the domain (`pkt[DNSQR].qname`).
   - `get_or_create_device()` — creates a `Device` row on first sighting,
     otherwise updates `last_seen`.
   - `blocklist.is_blocked()` — checks the domain against `BlockedEntry`.
   - Writes an `ActivityLog` row with status `allowed` or `blocked`.
4. Runs forever until you stop it (Ctrl+C).

---

## 5. File-by-file reference

| File | Role |
|---|---|
| `config.py` | All settings in one place — network interface, DB path, admin credentials, block method. Edit this first. |
| `models.py` | Database schema: `Device`, `ActivityLog`, `BlockedEntry`. |
| `blocklist.py` | Decides if something is blocked (`is_blocked`) and actually enforces it at the OS level (`enforce_block` → writes dnsmasq/iptables rules). |
| `sniffer.py` | Background process. Captures DNS packets, logs activity. Run with `sudo`. |
| `app.py` | The Flask web app — login, dashboard page, JSON API. This is your "main" file for the website. |
| `templates/base.html` | Shared HTML shell (loads the CSS). |
| `templates/login.html` | Admin sign-in page. |
| `templates/dashboard.html` | The dashboard layout: device list, activity table, blocklist form. |
| `static/css/style.css` | All styling. |
| `static/js/dashboard.js` | Polls the API every 4s and updates the tables without a page reload. |
| `requirements.txt` | Python package list for `pip install -r requirements.txt`. |
| `setup_pi.sh` | One-time script to install everything on a fresh Pi. |

---

## 6. Folder layout

```
.
├── README.md            <- this file
├── setup_pi.sh           <- one-time installer, run from here
└── networkmonitor/       <- the actual project (everything below runs from inside this folder)
    ├── app.py
    ├── sniffer.py
    ├── blocklist.py
    ├── models.py
    ├── config.py
    ├── requirements.txt
    ├── templates/
    └── static/
```

Keep `app.py` and `sniffer.py` running from *inside* `networkmonitor/` —
they use relative paths (e.g. `guardspot.db` gets created next to them).

## 7. Running it (dev/testing on a laptop first)

You can develop and test everything **before** touching a real Pi — the
sniffer just won't see real traffic unless you point it at a real interface
with actual DNS traffic on it (or feed it a `.pcap` file with scapy's
`sniff(offline="file.pcap", ...)` for testing).

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r networkmonitor/requirements.txt

cd networkmonitor

# Terminal 1 — website
python3 app.py

# Terminal 2 — packet capture (needs root; on the real Pi, once it's
# actually the hotspot, CAPTURE_INTERFACE in config.py must match)
sudo ../venv/bin/python3 sniffer.py
```

Then visit `http://localhost:5000`, log in with the credentials from
`config.py`, and you'll see the dashboard update live as `sniffer.py` logs
DNS activity.

## 8. Deploying for real on the Pi

1. Flash Raspberry Pi OS Lite, SSH in.
2. Run `setup_pi.sh`.
3. Configure `hostapd` + `dnsmasq` so the Pi broadcasts its own Wi-Fi
   network and hands out DHCP/DNS to connected devices (this is what makes
   the Pi see *everyone's* traffic, not just its own).
4. Set `CAPTURE_INTERFACE = "wlan0"` in `config.py` (or whatever interface
   `hostapd` uses).
5. Set real `ADMIN_USERNAME` / `ADMIN_PASSWORD` / `SECRET_KEY` via
   environment variables — don't leave the defaults in production.
6. Optional but recommended: create `systemd` service units for `app.py`
   and `sniffer.py` so both start automatically on boot and restart if they
   crash.
7. From your phone/laptop connected to that Wi-Fi (or on the same LAN),
   browse to `http://<pi-ip>:5000`.

---

## 9. Things still worth adding (not yet in this version)

- Resolving and storing `resolved_ip` from the DNS *response* packet, not
  just the query (needed if you want to block by IP after first seeing a
  domain resolve).
- HTTPS for the dashboard itself (currently plain HTTP — fine on a trusted
  LAN, not fine if exposed to the internet).
- Rate limiting / login lockout on `/login`.
- MAC-address-based device naming (currently only IP-based; IPs can change
  on DHCP renewal).
- A `systemd` unit file example for auto-start (mentioned above but not
  included here — happy to add if useful).
