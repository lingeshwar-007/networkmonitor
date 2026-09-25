#!/bin/bash
# GuardSpot domain block test
# Usage: ./test_domain_block.sh tiktok.com [pi-ip]

set -e
DOMAIN="$1"
PI_IP="${2:-127.0.0.1}"

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain> [pi-ip]"
    exit 1
fi

echo "Checking /etc/dnsmasq.d/guardspot_blocklist.conf for '$DOMAIN'..."
grep "$DOMAIN" /etc/dnsmasq.d/guardspot_blocklist.conf 2>/dev/null && echo "  -> Entry found in blocklist file." || echo "  -> NOT in blocklist file (add it via the dashboard first)."

echo ""
echo "Querying DNS for '$DOMAIN' via $PI_IP..."
RESULT=$(dig +short "$DOMAIN" @"$PI_IP" | tail -n1)
echo "  -> Resolved to: ${RESULT:-<no response>}"

if [ "$RESULT" == "0.0.0.0" ]; then
    echo "BLOCKED correctly."
else
    echo "NOT BLOCKED at DNS level. Check dnsmasq.conf includes the guardspot_blocklist.conf file, then: sudo systemctl restart dnsmasq"
fi
