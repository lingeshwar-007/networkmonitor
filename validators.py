"""
validators.py
--------------
Input validation for anything that reaches the SSH connector or the
database. SQLAlchemy already parameterizes every query it builds (we never
write raw SQL anywhere in this project), so classic SQL injection isn't
actually possible through the ORM calls in blocklist.py/models.py — but we
still validate shape/format here as defense in depth, and to reject junk
before it ever reaches paramiko or the DB.
"""

import re

IPV4_RE = re.compile(
    r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$"
)

# Linux usernames: lowercase letters, digits, underscore, hyphen; must start with a letter/underscore
SSH_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")

# Domain names: labels of letters/digits/hyphens separated by dots
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def normalize_domain(value: str) -> str:
    """Strips http(s)://, paths, query params, ports, and leading www./trailing dots."""
    val = (value or "").strip().lower()
    if "://" in val:
        val = val.split("://", 1)[1]
    val = val.split("/")[0].split("?")[0].split(":")[0]
    if val.startswith("www."):
        val = val[4:]
    return val.strip(".")


HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,61}[a-zA-Z0-9])?$")


def is_valid_ipv4(value: str) -> bool:
    return bool(IPV4_RE.match(value or ""))


def is_valid_host(value: str) -> bool:
    """Accepts valid IPv4 address or hostname (e.g. 'guardspot', 'guardspot.local')."""
    if not value:
        return False
    val = value.strip().lower()
    return is_valid_ipv4(val) or bool(HOSTNAME_RE.match(val))


def is_valid_ssh_username(value: str) -> bool:
    return bool(SSH_USERNAME_RE.match(value or ""))


def is_valid_domain(value: str) -> bool:
    norm = normalize_domain(value)
    return bool(DOMAIN_RE.match(norm))


def is_valid_block_value(value: str, entry_type: str) -> bool:
    if entry_type == "ip":
        return is_valid_ipv4(value)
    if entry_type == "domain":
        return is_valid_domain(value)
    return False

