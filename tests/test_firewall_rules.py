import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import firewall


class FirewallRuleTests(unittest.TestCase):
    def test_blocked_device_is_dropped_by_mac_for_ipv4_and_ipv6(self):
        v4, v6 = firewall.build_rules(macs=["AA:BB:CC:DD:EE:FF"])
        expected = "-A GUARDSPOT -m mac --mac-source AA:BB:CC:DD:EE:FF -j DROP"
        self.assertIn(expected, v4)
        self.assertIn(expected, v6)

    def test_unknown_mac_device_is_dropped_by_source_and_destination_ip(self):
        v4, v6 = firewall.build_rules(device_ips=["192.168.4.12"])
        self.assertIn("-A GUARDSPOT -s 192.168.4.12 -j DROP", v4)
        self.assertIn("-A GUARDSPOT -d 192.168.4.12 -j DROP", v4)
        self.assertFalse(any("192.168.4.12" in rule for rule in v6))

    def test_blocked_domains_use_authoritative_local_dns_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "blocked_domains.servers"
            with patch.object(firewall, "SERVERS_FILE", str(target)):
                self.assertTrue(firewall._write_dns_rules(["example.com", "sub.example.net"]))
            self.assertEqual(
                "# Managed by GuardSpot - do not edit. Rebuilt from the database.\n"
                "local=/example.com/\n"
                "local=/sub.example.net/\n",
                target.read_text(),
            )

    def test_site_blocks_reject_quic_and_match_ipv6_sni(self):
        v4, v6 = firewall.build_rules(sni_domains=["example.com"], quic=True)
        self.assertTrue(any("--dport 443" in rule and "-p udp" in rule for rule in v4))
        self.assertTrue(any("--dport 443" in rule and "-p udp" in rule for rule in v6))
        self.assertTrue(any("example.com" in rule and "-p tcp" in rule for rule in v6))


if __name__ == "__main__":
    unittest.main()
