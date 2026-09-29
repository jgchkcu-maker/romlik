import unittest

from decorate_subscription import (
    LOCAL_OBSERVATIONS,
    happ_text,
    select_local_nodes,
    select_visible_nodes,
    source_country_hint,
)


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

    def test_local_feed_prefers_device_observed_route(self):
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

        observed_grpc = node(
            "176.108.246.110",
            pool="whitelist",
            source="mobile",
            score=0,
            mobile=True,
            uri="vless://5d16ac22-6eea-426f-b778-6f4c2961faef@176.108.246.110:9830?encryption=none&pbk=bnRIb3Er1i-K6NGGByCO9UbGfOvu43ZoiK7ulPd1SzU&security=reality&serviceName=grpc-tunnel&sni=dl.google.com&type=grpc&fp=firefox",
        )
        observed_grpc["verified"] = False
        observed_grpc["happ_probe_ok"] = False
        observed_grpc["port"] = 9830

        selected = select_local_nodes([verified], [observed_grpc], limit=10)
        self.assertEqual("176.108.246.110", selected[0]["host"])

    def test_source_country_hint_uses_feed_country_not_entry_ip_geo(self):
        self.assertEqual(
            "🇦🇹 Austria",
            source_country_hint({"remark": "🇦🇹 Austria | [*CIDR]"}),
        )
        self.assertEqual(
            "🇬🇧 United Kingdom",
            source_country_hint({"remark": "🇬🇧 United Kingdom [*CIDR]"}),
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
