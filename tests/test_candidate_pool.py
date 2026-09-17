import unittest

from candidate_pool import select_candidates


def node(host, *, pool="normal", source="src", score=10, mobile=False, uri=None, port=443):
    uri = uri or f"vless://user-{host}@{host}:{port}?security=reality&pbk=key-{host}&sid=aa&sni=example.com&type=tcp"
    return {
        "uri": uri,
        "protocol": "vless",
        "host": host,
        "port": port,
        "pool": pool,
        "source": source,
        "score": score,
        "mbps": score,
        "latency_ms": 100,
        "mobile_candidate": mobile,
    }


class CandidatePoolTests(unittest.TestCase):
    def test_duplicate_logical_backends_collapse_to_one_visible_candidate(self):
        a = node(
            "169.40.42.15",
            uri="vless://same-user@169.40.42.15:443?security=reality&pbk=same-key&sid=aa&sni=yahoo.com&type=tcp&flow=xtls-rprx-vision",
            score=20,
        )
        b = node(
            "169.40.42.212",
            uri="vless://same-user@169.40.42.212:443?security=reality&pbk=same-key&sid=aa&sni=yahoo.com&type=tcp&flow=xtls-rprx-vision",
            score=10,
        )
        selected = select_candidates([a, b], [], [], total_limit=100, whitelist_limit=40)
        self.assertEqual(1, len(selected))
        self.assertEqual("169.40.42.15", selected[0]["host"])

    def test_mobile_candidates_survive_without_azure_metrics(self):
        mobile = node("5.129.198.223", pool="whitelist", source="igareck-mobile", score=0, mobile=True)
        mobile["score"] = None
        mobile["mbps"] = None
        mobile["latency_ms"] = None
        selected = select_candidates([], [], [mobile], total_limit=100, whitelist_limit=40)
        self.assertEqual([mobile["host"]], [x["host"] for x in selected])

    def test_total_and_whitelist_limits_are_enforced(self):
        normal = [node(f"10.{i // 250}.{i % 250}.1", score=200 - i) for i in range(120)]
        mobile = [node(f"172.16.{i}.1", pool="whitelist", source="mobile", score=0, mobile=True) for i in range(60)]
        selected = select_candidates(normal, [], mobile, total_limit=100, whitelist_limit=40)
        self.assertLessEqual(len(selected), 100)
        self.assertLessEqual(sum(1 for x in selected if x.get("pool") == "whitelist"), 40)

    def test_diversity_pass_does_not_fill_list_from_one_ipv4_prefix(self):
        same_prefix = [node(f"169.40.42.{i}", source="big-source", score=200 - i) for i in range(1, 20)]
        other_prefixes = [node(f"203.0.{i}.10", source=f"source-{i}", score=100 - i) for i in range(1, 10)]
        selected = select_candidates(same_prefix + other_prefixes, [], [], total_limit=10, whitelist_limit=0)
        first_ten = selected[:10]
        from_same_prefix = sum(1 for x in first_ten if x["host"].startswith("169.40.42."))
        self.assertLessEqual(from_same_prefix, 4)
        self.assertGreaterEqual(len({x["source"] for x in first_ten}), 3)


if __name__ == "__main__":
    unittest.main()
