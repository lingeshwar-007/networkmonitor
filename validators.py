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


def is_valid_ipv4(value: str) -> bool:
    return bool(IPV4_RE.match(value or ""))


def is_valid_ssh_username(value: str) -> bool:
    return bool(SSH_USERNAME_RE.match(value or ""))


def is_valid_domain(value: str) -> bool:
    return bool(DOMAIN_RE.match(value or ""))


def is_valid_block_value(value: str, entry_type: str) -> bool:
    if entry_type == "ip":
        return is_valid_ipv4(value)
    if entry_type == "domain":
        return is_valid_domain(value)
    return False
