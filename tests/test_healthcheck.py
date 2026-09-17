import unittest

from healthcheck import validate_visible_records


class HealthcheckTests(unittest.TestCase):
    def test_duplicate_visible_identity_is_an_error(self):
        records = [
            {"identity": "same", "pool": "normal", "mobile_candidate": False},
            {"identity": "same", "pool": "normal", "mobile_candidate": False},
        ]
        result = validate_visible_records(records, expected_count=2)
        self.assertEqual(2, result["visible"])
        self.assertEqual(1, result["unique"])
        self.assertEqual(["same"], result["duplicates"])
        self.assertTrue(any("duplicate" in e.lower() for e in result["errors"]))

    def test_visible_whitelist_limit_and_count_mismatch_are_errors(self):
        records = [
            {"identity": f"w{i}", "pool": "whitelist", "mobile_candidate": i < 2}
            for i in range(5)
        ]
        result = validate_visible_records(
            records,
            expected_count=6,
            total_limit=100,
            whitelist_limit=4,
        )
        self.assertEqual(5, result["visible"])
        self.assertEqual(5, result["whitelist"])
        self.assertEqual(2, result["mobile"])
        self.assertTrue(any("whitelist" in e.lower() for e in result["errors"]))
        self.assertTrue(any("mismatch" in e.lower() for e in result["errors"]))

    def test_clean_visible_pool_passes(self):
        records = [
            {"identity": "a", "pool": "normal", "mobile_candidate": False},
            {"identity": "b", "pool": "whitelist", "mobile_candidate": True},
        ]
        result = validate_visible_records(records, expected_count=2)
        self.assertEqual([], result["errors"])
        self.assertEqual(2, result["unique"])


if __name__ == "__main__":
    unittest.main()
