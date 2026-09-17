import unittest

from decorate_subscription import happ_text


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


if __name__ == "__main__":
    unittest.main()
