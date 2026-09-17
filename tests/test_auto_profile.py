import unittest

from auto_profile import build_subscription, select_country_balanced


class AutoProfileTests(unittest.TestCase):
    def _node(self, idx, country="US", pool="normal", mobile=False):
        return {
            "uri": f"vless://00000000-0000-0000-0000-{idx:012d}@203.0.{idx // 250}.{idx % 250 + 1}:443?encryption=none&security=none&type=tcp",
            "protocol": "vless",
            "host": f"203.0.{idx // 250}.{idx % 250 + 1}",
            "port": 443,
            "source": f"source-{idx % 7}",
            "pool": pool,
            "country_code": country,
            "country": country,
            "mobile_candidate": mobile,
            "score": 1000 - idx,
            "mbps": 100 - idx / 10,
            "latency_ms": 20 + idx,
            "server_identity": f"id-{idx}",
        }

    def test_normal_country_cap_prevents_one_country_flood(self):
        nodes = [self._node(i, "US") for i in range(30)]
        nodes += [self._node(100 + i, "DE") for i in range(10)]
        nodes += [self._node(200 + i, "NL") for i in range(10)]
        nodes += [self._node(300 + i, "FR") for i in range(10)]

        selected = select_country_balanced(nodes, [], total_limit=40, per_country_limit=10)
        us = [n for n in selected if n.get("country_code") == "US"]
        self.assertEqual(len(selected), 40)
        self.assertLessEqual(len(us), 10)

    def test_subscription_contains_one_json_config_with_least_ping_pool(self):
        nodes = [self._node(1, "US"), self._node(2, "DE")]
        payload = build_subscription(nodes)

        self.assertEqual(len(payload), 1)
        cfg = payload[0]
        self.assertTrue(cfg["remarks"].startswith("⚡ AUTO"))
        proxy_outbounds = [x for x in cfg["outbounds"] if x.get("tag", "").startswith("proxy-")]
        self.assertEqual(len(proxy_outbounds), 2)
        self.assertEqual(cfg["routing"]["balancers"][0]["strategy"]["type"], "leastPing")
        self.assertEqual(cfg["routing"]["balancers"][0]["selector"], ["proxy-"])
        self.assertEqual(cfg["observatory"]["subjectSelector"], ["proxy-"])
        self.assertTrue(cfg["observatory"]["enableConcurrency"])
        self.assertEqual(cfg["inbounds"][0]["port"], 10808)

    def test_tls_outbound_does_not_emit_removed_allow_insecure(self):
        node = self._node(9, "DE")
        node["uri"] = (
            "vless://00000000-0000-0000-0000-000000000009@203.0.0.10:443"
            "?encryption=none&security=tls&sni=example.com&type=ws&path=%2Fws&host=example.com"
        )
        payload = build_subscription([node])
        proxy = next(x for x in payload[0]["outbounds"] if x.get("tag") == "proxy-001")
        tls = proxy["streamSettings"]["tlsSettings"]
        self.assertNotIn("allowInsecure", tls)


if __name__ == "__main__":
    unittest.main()
