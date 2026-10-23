"""
firewall.py
-----------
Linux gateway enforcement for GuardSpot (Raspberry Pi acting as the Wi-Fi
access point / router).

How it works
============
The database is the single source of truth.  Whenever anything changes (a
website/app/IP is blocked or unblocked, a device is blocked or unblocked, or
GuardSpot starts) blocklist.py calls apply() with the COMPLETE desired state
and this module makes the machine match it.  Because the whole state is
rebuilt every time, rules can never get out of sync, duplicated, or
half-removed (the old per-rule insert/delete approach could do all three).

Four layers are managed:

1. DNS sinkhole    - every blocked domain (and its sub-domains and the CDN /
                     app domains it expands to) is written to a dnsmasq
                     "servers-file".  dnsmasq re-reads that file on SIGHUP, so
                     changes apply instantly.  (The previous code appended
                     address=/.../ lines to a normal config file and sent
                     SIGHUP, but dnsmasq does NOT re-read normal config files
                     on SIGHUP, so website blocks silently never took effect.)
2. DNS lock-in     - all client port-53 traffic is redirected to the Pi, and
                     DNS-over-TLS / well-known DNS-over-HTTPS resolvers are
                     rejected, so clients cannot dodge the sinkhole by using
                     their own resolver.
3. Packet filter   - a dedicated iptables chain (GUARDSPOT) that is always the
                     FIRST rule of FORWARD and INPUT.  It holds: blocked
                     devices (by MAC, falling back to IP), blocked IP/CIDR
                     ranges, and an SNI / Host-header string match so a
                     blocked site is refused even if the client already knows
                     its IP address.  QUIC (UDP/443) is rejected while a site
                     block is active so browsers fall back to TCP, where the
                     SNI match works.
4. Verification    - after applying, a real DNS query is sent to the Pi's own
                     resolver to prove the sinkhole is live.  status() reports
                     every prerequisite so the dashboard can show WHY a block
                     is not being enforced instead of silently pretending.

Everything here is Linux-only and needs root (or passwordless sudo).
"""

import ipaddress
import os
import platform
import re
import shutil
import socket
import struct
import subprocess
import threading
import time
from collections import deque
from contextlib import contextmanager

CHAIN = "GUARDSPOT"
NAT_CHAIN = "GUARDSPOT_NAT"
NAT6_CHAIN = "GUARDSPOT_NAT6"

STATE_DIR = "/etc/guardspot"
SERVERS_FILE = os.path.join(STATE_DIR, "blocked_domains.servers")
DNSMASQ_CONF_DIRS = ["/etc/dnsmasq.d", "/etc/NetworkManager/dnsmasq-shared.d"]
INCLUDE_FILE = "guardspot.conf"
# Files written by older GuardSpot versions. They must go: they hold stale
# address=/.../ blocks and dhcp-host=...,ignore lines that never get removed.
LEGACY_FILES = ("guardspot_blocklist.conf", "guardspot_deny.conf")
LOCK_FILE = "/run/guardspot-firewall.lock"

# Well-known public DNS-over-HTTPS resolvers.  Rejecting port 443 to these
# stops browsers/phones using DoH to bypass the Pi's DNS sinkhole.
PUBLIC_DOH_V4 = [
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220",
]
PUBLIC_DOH_V6 = [
    "2606:4700:4700::1111", "2606:4700:4700::1001",
    "2001:4860:4860::8888", "2001:4860:4860::8844", "2620:fe::fe",
]

_MAC_RE = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")
_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")

_lock = threading.RLock()
_errors = deque(maxlen=50)
_last_apply = {"ok": None, "warnings": [], "time": None}


class FirewallError(Exception):
    pass


# ------------------------------------------------------------------ helpers

def is_linux() -> bool:
    return platform.system() == "Linux"


def _cmd(cmd, stdin=None, timeout=20):
    """Run a command (through `sudo -n` when not root). Never raises."""
    cmd = list(cmd)
    if hasattr(os, "geteuid") and os.geteuid() != 0 and shutil.which("sudo"):
        cmd = ["sudo", "-n"] + cmd
    try:
        return subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        _errors.append(f"command not found: {cmd[0] if cmd[0] != 'sudo' else cmd[2]}")
        return subprocess.CompletedProcess(cmd, 127, "", "command not found")
    except subprocess.TimeoutExpired:
        _errors.append(f"timed out: {' '.join(cmd)}")
        return subprocess.CompletedProcess(cmd, 124, "", "timed out")
    except Exception as e:  # pragma: no cover - defensive
        _errors.append(f"{' '.join(cmd)}: {e}")
        return subprocess.CompletedProcess(cmd, 1, "", str(e))


def have_privileges() -> bool:
    if not is_linux():
        return False
    if os.geteuid() == 0:
        return True
    if not shutil.which("sudo"):
        return False
    return subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0


@contextmanager
def _process_lock():
    """Serialise apply() across the web app and the sniffer (separate processes)."""
    fh = None
    try:
        import fcntl
        fh = open(LOCK_FILE, "w")
        fcntl.flock(fh, fcntl.LOCK_EX)
    except Exception:
        fh = None
    try:
        yield
    finally:
        if fh:
            try:
                fh.close()
            except Exception:
                pass


def _ipt(v6: bool) -> str:
    return "ip6tables" if v6 else "iptables"


def default_uplink():
    """Interface that holds the default route (the Pi's connection to the internet)."""
    try:
        with open("/proc/net/route") as f:
            next(f)
            for line in f:
                p = line.split()
                if len(p) > 3 and p[1] == "00000000" and int(p[3], 16) & 2:
                    return p[0]
    except Exception:
        pass
    return None


def iface_ipv4(iface):
    """IPv4 address of a Linux interface name (stdlib only, no `ip` binary needed)."""
    try:
        import fcntl
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            packed = fcntl.ioctl(s.fileno(), 0x8915, struct.pack("256s", iface[:15].encode()))
        finally:
            s.close()
        return socket.inet_ntoa(packed[20:24])
    except Exception:
        return None


def local_dns_listening() -> bool:
    """Is a DNS server (dnsmasq) listening on UDP port 53 on this machine?"""
    r = subprocess.run(["ss", "-H", "-lun"], capture_output=True, text=True) if shutil.which("ss") else None
    if r and r.returncode == 0:
        return any(re.search(r"[:\]]53\s", line) for line in r.stdout.splitlines())
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("0.0.0.0", 53))
        s.close()
        return False
    except OSError:
        return True


# ---------------------------------------------------------- input cleaning

def _clean_mac(v):
    v = (v or "").strip().upper().replace("-", ":")
    return v if _MAC_RE.match(v) else None


def _clean_net(v):
    try:
        return ipaddress.ip_network((v or "").strip(), strict=False)
    except ValueError:
        return None


def _clean_domain(v):
    v = (v or "").strip().lower().strip(".")
    return v if _DOMAIN_RE.match(v) else None


# ------------------------------------------------------------ rule builder

def build_rules(macs=(), device_ips=(), block_nets=(), sni_domains=(),
                doh=True, dot=True, quic=True):
    """
    Pure function: returns (v4_rules, v6_rules) as lists of iptables-restore
    lines for the GUARDSPOT chain.  Inputs must already be cleaned.
    """
    A = f"-A {CHAIN}"
    v4, v6 = [], []

    # 1. Blocked devices: silent DROP, by MAC (works across IP changes).
    for mac in sorted(macs):
        v4.append(f"{A} -m mac --mac-source {mac} -j DROP")
        v6.append(f"{A} -m mac --mac-source {mac} -j DROP")
    for ip in sorted(device_ips):  # only devices whose MAC is unknown
        v4.append(f"{A} -s {ip} -j DROP")
        v4.append(f"{A} -d {ip} -j DROP")

    # 2. Encrypted-DNS bypass: DoT everywhere, DoH to the well-known resolvers.
    if dot:
        for L, tcp_rej in ((v4, "tcp-reset"), (v6, "tcp-reset")):
            L.append(f"{A} -p tcp --dport 853 -j REJECT --reject-with {tcp_rej}")
            L.append(f"{A} -p udp --dport 853 -j DROP")
    if doh:
        for ip in PUBLIC_DOH_V4:
            v4.append(f"{A} -d {ip} -p tcp --dport 443 -j REJECT --reject-with tcp-reset")
            v4.append(f"{A} -d {ip} -p udp --dport 443 -j DROP")
        for ip in PUBLIC_DOH_V6:
            v6.append(f"{A} -d {ip} -p tcp --dport 443 -j REJECT --reject-with tcp-reset")
            v6.append(f"{A} -d {ip} -p udp --dport 443 -j DROP")

    # 3. Blocked destination IPs / CIDR ranges (dedicated app ranges, IP entries).
    for net in sorted(block_nets, key=lambda n: (n.version, str(n))):
        L, unreach = (v6, "icmp6-port-unreachable") if net.version == 6 else (v4, "icmp-port-unreachable")
        L.append(f"{A} -d {net} -p tcp -j REJECT --reject-with tcp-reset")
        L.append(f"{A} -d {net} -j REJECT --reject-with {unreach}")

    # 4. SNI / Host-header match for blocked sites on HTTPS and HTTP.  Only the
    #    first packets of each connection are inspected (cheap on a Pi).
    if sni_domains:
        if quic:
            v4.append(f"{A} -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable")
            v6.append(f"{A} -p udp --dport 443 -j REJECT --reject-with icmp6-port-unreachable")
        for d in sorted(sni_domains):
            rule = (f'{A} -p tcp -m multiport --dports 80,443 '
                    f'-m connbytes --connbytes 0:10 --connbytes-dir original --connbytes-mode packets '
                    f'-m string --string "{d}" --algo bm -j REJECT --reject-with tcp-reset')
            v4.append(rule)
            v6.append(rule)
    return v4, v6


def _ensure_chain(v6, table, chain, hooks):
    t = [_ipt(v6), "-t", table]
    if _cmd(t + ["-n", "-L", chain]).returncode != 0:
        r = _cmd(t + ["-N", chain])
        if r.returncode != 0:
            raise FirewallError(f"cannot create {_ipt(v6)} chain {chain}: {r.stderr.strip()}")
    want = f"-A {{hook}} -j {chain}"
    for hook in hooks:
        out = _cmd(t + ["-S", hook]).stdout.splitlines()
        rules = [l.strip() for l in out if l.startswith("-A ")]
        w = want.format(hook=hook)
        if rules and rules[0] == w and rules.count(w) == 1:
            continue  # already the first rule, exactly once
        for _ in range(10):  # drop every stale/misplaced jump, then insert on top
            if _cmd(t + ["-D", hook, "-j", chain]).returncode != 0:
                break
        r = _cmd(t + ["-I", hook, "1", "-j", chain])
        if r.returncode != 0:
            raise FirewallError(f"cannot hook {chain} into {hook}: {r.stderr.strip()}")


def _load_chain(v6, table, chain, lines):
    """Atomically (re)fill one user chain."""
    t = [_ipt(v6), "-t", table]
    _cmd(t + ["-F", chain])
    payload = f"*{table}\n:{chain} - [0:0]\n" + "".join(l + "\n" for l in lines) + "COMMIT\n"
    r = _cmd([_ipt(v6) + "-restore", "--noflush"], stdin=payload)
    if r.returncode != 0:
        raise FirewallError(f"{_ipt(v6)}-restore failed: {r.stderr.strip()}")


# ----------------------------------------------------------------- DNS side

def _write_atomic(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(content)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def _read(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return None


def _write_dns_rules(domains) -> bool:
    """Write a dnsmasq local-zone file that never forwards blocked domains.

    ``local=/domain/`` makes dnsmasq authoritative for the zone and returns
    NXDOMAIN/NODATA instead of forwarding the request upstream. This is more
    portable than relying on empty ``server=/domain/`` behavior.
    """
    content = "# Managed by GuardSpot - do not edit. Rebuilt from the database.\n"
    content += "".join(f"local=/{d}/\n" for d in sorted(domains))
    if _read(SERVERS_FILE) == content:
        return False
    _write_atomic(SERVERS_FILE, content)
    return True


def _ensure_dns_includes():
    """Make sure each dnsmasq conf dir loads our servers-file. Returns dirs where
    the include was newly created (dnsmasq needs one full restart to see it)."""
    include = f"# Managed by GuardSpot\nservers-file={SERVERS_FILE}\n"
    created = []
    for d in DNSMASQ_CONF_DIRS:
        if d == "/etc/dnsmasq.d" and not os.path.isdir(d) and shutil.which("dnsmasq"):
            os.makedirs(d, exist_ok=True)
        if not os.path.isdir(d):
            continue
        path = os.path.join(d, INCLUDE_FILE)
        if _read(path) != include:
            _write_atomic(path, include)
            created.append(d)
    return created


def _remove_legacy() -> bool:
    removed = False
    for d in DNSMASQ_CONF_DIRS:
        for name in LEGACY_FILES:
            p = os.path.join(d, name)
            if os.path.exists(p):
                try:
                    os.remove(p)
                    removed = True
                except OSError as e:
                    _errors.append(f"cannot remove legacy file {p}: {e}")
    return removed


def reload_dns() -> bool:
    """SIGHUP every dnsmasq so it re-reads the servers-file."""
    return _cmd(["pkill", "-HUP", "-x", "dnsmasq"]).returncode == 0


def restart_dns() -> bool:
    if _cmd(["systemctl", "is-active", "--quiet", "dnsmasq"]).returncode == 0:
        return _cmd(["systemctl", "restart", "dnsmasq"]).returncode == 0
    return False


def dns_query(name, server, qtype=1, port=53, timeout=1.5):
    """Minimal DNS client (stdlib). Returns (rcode, [ipv4 answers])."""
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.strip(".").split(".")) + b"\x00"
    pkt = os.urandom(2) + struct.pack(">HHHHH", 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", qtype, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (server, port))
        data = s.recv(2048)
    finally:
        s.close()
    rcode = data[3] & 0x0F
    qd, an = struct.unpack(">HH", data[4:8])

    def skip(off):
        while True:
            ln = data[off]
            if ln == 0:
                return off + 1
            if ln & 0xC0 == 0xC0:
                return off + 2
            off += ln + 1

    off = 12
    for _ in range(qd):
        off = skip(off) + 4
    ips = []
    for _ in range(an):
        off = skip(off)
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        if rtype == 1 and rdlen == 4:
            ips.append(socket.inet_ntoa(data[off:off + 4]))
        off += rdlen
    return rcode, ips


def verify_dns_block(domain, iface=None):
    """Ask the Pi's own resolver for a blocked domain. Returns (ok, detail)."""
    server = (iface_ipv4(iface) if iface else None) or "127.0.0.1"
    try:
        rcode, ips = dns_query(domain, server)
    except Exception as e:
        return False, f"resolver {server} did not answer ({e})"
    if rcode == 3 or (ips and all(ip == "0.0.0.0" for ip in ips)):
        return True, f"{domain} is blocked at resolver {server}"
    return False, f"resolver {server} still resolves {domain} ({', '.join(ips) or 'rcode %d' % rcode})"


# --------------------------------------------------------------- main entry

def init_system(iface=None, uplink=None):
    """One-time-per-start plumbing: forwarding, conntrack accounting, NAT."""
    warnings = []
    if not is_linux():
        return ["not a Linux host"]
    _cmd(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    _cmd(["modprobe", "nf_conntrack"])
    _cmd(["sysctl", "-w", "net.netfilter.nf_conntrack_acct=1"])  # needed by the connbytes match
    uplink = uplink or default_uplink()
    if uplink and uplink != iface:
        if _cmd(["iptables", "-t", "nat", "-C", "POSTROUTING", "-o", uplink, "-j", "MASQUERADE"]).returncode != 0:
            r = _cmd(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", uplink, "-j", "MASQUERADE"])
            if r.returncode != 0:
                warnings.append(f"could not enable NAT out of {uplink}: {r.stderr.strip()}")
    elif not uplink:
        warnings.append("no default route found - the Pi has no internet uplink to NAT out of")
    return warnings


def apply(*, dns_domains=(), sni_domains=None, cidrs=(), block_ips=(), macs=(), device_ips=(),
          iface=None, uplink=None, block_doh=True, block_dot=True, sni_filter=True,
          block_quic=True, flush_all=False, flush_ips=()):
    """
    Make the machine match the desired state. Returns
    {"ok": bool, "warnings": [...], "counts": {...}}.
    """
    result = {"ok": False, "warnings": [], "counts": {}}
    if not is_linux():
        result["warnings"].append("Firewall enforcement needs a Linux gateway (Raspberry Pi).")
        return result
    if not have_privileges():
        result["warnings"].append(
            "GuardSpot is not running as root, so firewall rules cannot be applied. "
            "Run it with sudo or use the guardspot-web service (User=root).")
        _last_apply.update(result, time=time.time())
        return result

    domains = sorted({d for d in (_clean_domain(x) for x in dns_domains) if d})
    sni = sorted({d for d in (_clean_domain(x) for x in (domains if sni_domains is None else sni_domains)) if d})
    macs_c = {m for m in (_clean_mac(x) for x in macs) if m}
    nets = {n for n in (_clean_net(x) for x in list(cidrs) + list(block_ips)) if n}
    dev_ips = set()
    for ip in device_ips:
        try:
            dev_ips.add(str(ipaddress.ip_address((ip or "").strip())))
        except ValueError:
            pass

    with _lock, _process_lock():
        warn = result["warnings"]
        v4, v6 = build_rules(macs_c, dev_ips, nets, sni if sni_filter else (), block_doh, block_dot,
                             block_quic)

        # ---- packet filter -------------------------------------------------
        for is6, rules in ((False, v4), (True, v6)):
            try:
                _ensure_chain(is6, "filter", CHAIN, ("FORWARD", "INPUT"))
                _load_chain(is6, "filter", CHAIN, rules)
            except FirewallError as e:
                (warn if is6 else warn).append(("IPv6: " if is6 else "") + str(e))
        if _cmd(["iptables", "-S", "FORWARD"]).stdout.startswith("-P FORWARD DROP"):
            warn.append("iptables FORWARD policy is DROP: add an ACCEPT rule from the hotspot interface "
                        "or clients will have no internet at all.")

        # ---- DNS redirect + NAT -------------------------------------------
        try:
            redirect = bool(iface) and local_dns_listening()
            _ensure_chain(False, "nat", NAT_CHAIN, ("PREROUTING",))
            nat_rules = []
            if redirect:
                for proto in ("udp", "tcp"):
                    nat_rules.append(f"-A {NAT_CHAIN} -i {iface} -p {proto} --dport 53 -j REDIRECT --to-ports 53")
            _load_chain(False, "nat", NAT_CHAIN, nat_rules)
            if not redirect:
                warn.append("No DNS server is listening on port 53 on this machine (dnsmasq stopped?), "
                            "so clients cannot be forced through GuardSpot's DNS filter.")
        except FirewallError as e:
            warn.append(str(e))
        # IPv4 REDIRECT does not cover IPv6 clients. Keep IPv6 DNS requests
        # on the gateway too, otherwise a dual-stack client can bypass the
        # domain sinkhole with its own resolver.
        try:
            redirect6 = bool(iface) and local_dns_listening()
            _ensure_chain(True, "nat", NAT6_CHAIN, ("PREROUTING",))
            nat6_rules = []
            if redirect6:
                for proto in ("udp", "tcp"):
                    nat6_rules.append(f"-A {NAT6_CHAIN} -i {iface} -p {proto} --dport 53 -j REDIRECT --to-ports 53")
            _load_chain(True, "nat", NAT6_CHAIN, nat6_rules)
        except FirewallError as e:
            warn.append("IPv6 DNS redirect: " + str(e))
        for w in init_system(iface, uplink):
            warn.append(w)

        # ---- DNS sinkhole --------------------------------------------------
        try:
            changed = _write_dns_rules(domains)
            created = _ensure_dns_includes()
            legacy = _remove_legacy()
            restarted = False
            if created or legacy:
                restarted = restart_dns()
                if not restarted:
                    warn.append("GuardSpot's DNS include was installed but dnsmasq could not be restarted. "
                                "If the hotspot uses NetworkManager, reconnect the hotspot once "
                                "(nmcli connection down/up <name>) so its dnsmasq loads the new rules.")
            elif changed:
                if not reload_dns():
                    warn.append("dnsmasq is not running, so website blocks are not being enforced at DNS level.")
            if domains and (changed or created or legacy):
                time.sleep(0.4)
            if domains:
                ok, detail = verify_dns_block(domains[0], iface)
                if not ok:
                    warn.append("DNS block self-test failed: " + detail +
                                ". Check that dnsmasq loads /etc/dnsmasq.d/guardspot.conf (conf-dir) and was restarted.")
        except OSError as e:
            warn.append(f"cannot write DNS block files: {e}")

        # ---- kill connections that were already open ----------------------
        if flush_all:
            _cmd(["conntrack", "-F"])
        for ip in set(flush_ips):
            try:
                ip = str(ipaddress.ip_address(ip))
            except ValueError:
                continue
            _cmd(["conntrack", "-D", "-s", ip])
            _cmd(["conntrack", "-D", "-d", ip])

        result["counts"] = {"domains": len(domains), "sni_patterns": len(sni), "ip_ranges": len(nets),
                            "devices_by_mac": len(macs_c), "devices_by_ip": len(dev_ips)}
        result["ok"] = not warn
    _last_apply.update(ok=result["ok"], warnings=list(result["warnings"]), time=time.time())
    return result


def last_apply():
    return dict(_last_apply)


def recent_errors():
    return list(_errors)


# ------------------------------------------------------------------- status

def status(iface=None, uplink=None, expect_domains=(), sni_filter=True):
    checks = []

    def add(name, ok, detail="", fix=""):
        checks.append({"name": name, "ok": bool(ok), "detail": detail, "fix": "" if ok else fix})

    def done():
        return {"ok": all(c["ok"] for c in checks), "checks": checks,
                "last_apply": last_apply(), "errors": recent_errors()[-5:]}

    if not is_linux():
        add("Linux gateway", False, "This machine is not Linux",
            "Real firewalling needs the Raspberry Pi acting as the Wi-Fi gateway. "
            "On a Windows hotspot only DNS sinkholing is possible, which can be bypassed.")
        return done()
    root = have_privileges()
    add("Root privileges", root, "can run iptables" if root else "cannot run iptables",
        "Start GuardSpot with sudo, or run the guardspot-web systemd service as root.")
    if not root:
        return done()
    add("iptables installed", bool(shutil.which("iptables")), "", "sudo apt install iptables")
    fwd = (_read("/proc/sys/net/ipv4/ip_forward") or "0").strip() == "1"
    add("IP forwarding", fwd, "enabled" if fwd else "disabled", "sudo sysctl -w net.ipv4.ip_forward=1")
    for hook in ("FORWARD", "INPUT"):
        out = [l.strip() for l in _cmd(["iptables", "-S", hook]).stdout.splitlines() if l.startswith("-A ")]
        add(f"GUARDSPOT first in {hook}", bool(out) and out[0] == f"-A {hook} -j {CHAIN}",
            "", "Click 'Re-apply rules' on the dashboard")
    listening = local_dns_listening()
    add("DNS server on port 53", listening, "dnsmasq is listening" if listening else "nothing listening",
        "sudo systemctl enable --now dnsmasq (and make sure the hotspot uses it)")
    if iface:
        redirected = _cmd(["iptables", "-t", "nat", "-C", NAT_CHAIN, "-i", iface, "-p", "udp", "--dport", "53",
                           "-j", "REDIRECT", "--to-ports", "53"]).returncode == 0
        add("Client DNS forced to Pi", redirected, f"{iface}: port 53 redirected" if redirected else "",
            "Click 'Re-apply rules' (needs dnsmasq running)")
        redirected6 = _cmd(["ip6tables", "-t", "nat", "-C", NAT6_CHAIN, "-i", iface, "-p", "udp", "--dport", "53",
                            "-j", "REDIRECT", "--to-ports", "53"]).returncode == 0
        add("IPv6 client DNS forced to Pi", redirected6,
            f"{iface}: IPv6 port 53 redirected" if redirected6 else "",
            "Click 'Re-apply rules' (needs dnsmasq and IPv6 NAT support)")
    up = uplink or default_uplink()
    if up:
        nat = _cmd(["iptables", "-t", "nat", "-C", "POSTROUTING", "-o", up, "-j", "MASQUERADE"]).returncode == 0
        add("NAT to internet", nat, f"masquerade on {up}" if nat else "", "Click 'Re-apply rules'")
    else:
        add("NAT to internet", False, "no default route", "Connect the Pi's uplink (eth0 or Wi-Fi client)")
    inc = any(_read(os.path.join(d, INCLUDE_FILE)) is not None for d in DNSMASQ_CONF_DIRS)
    add("dnsmasq loads GuardSpot rules", inc, "", "Click 'Re-apply rules', then restart dnsmasq / reconnect the hotspot")
    if sni_filter:
        acct = (_read("/proc/sys/net/netfilter/nf_conntrack_acct") or "0").strip() == "1"
        add("Conntrack accounting (SNI filter)", acct, "", "sudo sysctl -w net.netfilter.nf_conntrack_acct=1")
    domains = [d for d in (_clean_domain(x) for x in expect_domains) if d]
    if domains and inc:
        ok, detail = verify_dns_block(domains[0], iface)
        add("DNS block self-test", ok, detail, "Restart dnsmasq (or reconnect the hotspot) so it loads the rules")
    return done()
