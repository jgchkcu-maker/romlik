import unittest

from decorate_subscription import happ_text, select_visible_nodes


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

    def test_visible_nodes_use_diversity_pool_and_keep_mobile_candidates(self):
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
        self.assertIn("5.129.198.223", [x["host"] for x in selected])
        normal = [x for x in selected if x.get("pool") != "whitelist"]
        self.assertLessEqual(
            sum(1 for x in normal if x["host"].startswith("169.40.42.")),
            4,
        )


if __name__ == "__main__":
    unittest.main()
