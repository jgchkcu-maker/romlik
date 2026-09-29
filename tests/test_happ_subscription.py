import unittest

from decorate_subscription import happ_text, select_local_nodes, select_visible_nodes


def node(host, *, pool="normal", source="src", score=10, mobile=False, uri=None):
    uri = uri or f"vless://user-{host}@{host}:443?security=reality&pbk=key-{host}&sid=aa&sni=example.com&type=tcp"
    return {
        "uri": uri,
        "protocol": "vless",
        "host": host,
        "port": 443,
        "pool": pool,
        "source": source,
        "score": score,
        "mbps": score,
        "latency_ms": 100,
        "mobile_candidate": mobile,
        "happ_probe_ok": not mobile,
        "verified": not mobile,
    }


class HappSubscriptionTests(unittest.TestCase):
    def test_happ_text_enables_local_proxy_ping_and_lowest_delay(self):
        text = happ_text("Romlik Auto", ["vless://example"])
        expected = [
            "#profile-update-interval: 1",
            "#subscription-auto-update-open-enable: 1",
            "#ping-type: proxy",
            "#check-url-via-proxy: https://cp.cloudflare.com/generate_204",
            "#subscription-ping-onopen-enabled: 1",
            "#subscriptions-sort-type: ping",
            "#subscription-autoconnect-type: lowestdelay",
        ]
        for line in expected:
            with self.subTest(line=line):
                self.assertIn(line, text)

        self.assertIn("vless://example", text)

    def test_local_feed_includes_unverified_mobile_candidates_and_prefers_verified_443(self):
        verified = node(
            "95.215.108.36",
            pool="whitelist",
            source="verified",
            score=10,
            mobile=False,
            uri="vless://user@95.215.108.36:443?security=reality&type=tcp&sni=example.com",
        )
        verified["verified"] = True
        verified["happ_probe_ok"] = True

        mobile_443 = node(
            "91.240.87.237",
            pool="whitelist",
            source="mobile",
            score=0,
            mobile=True,
            uri="vless://user@91.240.87.237:443?security=reality&type=raw&sni=example.com",
        )
        mobile_443["verified"] = False
        mobile_443["happ_probe_ok"] = False

        mobile_grpc = node(
            "176.108.246.110",
            pool="whitelist",
            source="mobile",
            score=0,
            mobile=True,
            uri="vless://user@176.108.246.110:9830?security=reality&type=grpc&sni=example.com",
        )
        mobile_grpc["verified"] = False
        mobile_grpc["happ_probe_ok"] = False

        selected = select_local_nodes([verified], [mobile_grpc, mobile_443], limit=10)
        self.assertEqual(
            ["95.215.108.36", "91.240.87.237", "176.108.246.110"],
            [x["host"] for x in selected],
        )

    def test_visible_nodes_use_diversity_pool_and_exclude_unverified_mobile_candidates(self):
        same_prefix = [
            node(f"169.40.42.{i}", source="big-source", score=200 - i)
            for i in range(1, 20)
        ]
        other_prefixes = [
            node(f"203.0.{i}.10", source=f"source-{i}", score=100 - i)
            for i in range(1, 10)
        ]
        mobile = node(
            "5.129.198.223",
            pool="whitelist",
            source="igareck-mobile",
            score=0,
            mobile=True,
        )
        mobile["score"] = None
        mobile["mbps"] = None
        mobile["latency_ms"] = None

        selected = select_visible_nodes(
            same_prefix + other_prefixes,
            [],
            [mobile],
            total_limit=10,
            whitelist_limit=4,
        )

        self.assertLessEqual(len(selected), 10)
        self.assertNotIn("5.129.198.223", [x["host"] for x in selected])
        normal = [x for x in selected if x.get("pool") != "whitelist"]
        self.assertLessEqual(
            sum(1 for x in normal if x["host"].startswith("169.40.42.")),
            4,
        )


if __name__ == "__main__":
    unittest.main()
