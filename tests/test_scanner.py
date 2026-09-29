import unittest

from scanner import Node, decorate


class ScannerTests(unittest.TestCase):
    def test_decorate_handles_verified_node_without_speed_metrics(self):
        node = Node(
            uri="vless://user@example.com:443?security=none&type=tcp",
            protocol="vless",
            host="example.com",
            port=443,
            source="test",
            pool="whitelist",
            ok=True,
            happ_probe_ok=True,
            happ_probe_ms=123.4,
        )
        decorated = decorate(node, 1)
        self.assertIn("speed%20n/a", decorated)
        self.assertIn("123ms", decorated)


if __name__ == "__main__":
    unittest.main()
