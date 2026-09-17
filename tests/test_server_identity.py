import unittest

from server_identity import server_identity


class ServerIdentityTests(unittest.TestCase):
    def test_reality_variants_with_same_backend_keys_collapse_across_ips(self):
        a = "vless://d65cc14c-f53f-4fe2-b262-97856601319c@169.40.42.15:443?security=reality&flow=xtls-rprx-vision&pbk=e2RLf57Li_-MDZGE9ss1BWPgP54mqRb5PfXhW2jcVVg&sid=c39cc7310a&sni=yahoo.com&type=tcp&fp=chrome"
        b = "vless://d65cc14c-f53f-4fe2-b262-97856601319c@169.40.42.212:443?security=reality&flow=xtls-rprx-vision&pbk=e2RLf57Li_-MDZGE9ss1BWPgP54mqRb5PfXhW2jcVVg&sid=c39cc7310a&sni=yahoo.com&type=tcp&fp=ios"
        self.assertEqual(server_identity(a, "vless"), server_identity(b, "vless"))

    def test_reality_different_public_keys_remain_distinct(self):
        a = "vless://same-user@203.0.113.10:443?security=reality&pbk=key-one&sid=aa&sni=example.com&type=tcp&flow=xtls-rprx-vision"
        b = "vless://same-user@203.0.113.11:443?security=reality&pbk=key-two&sid=aa&sni=example.com&type=tcp&flow=xtls-rprx-vision"
        self.assertNotEqual(server_identity(a, "vless"), server_identity(b, "vless"))

    def test_reality_different_transport_service_remains_distinct(self):
        a = "vless://same-user@203.0.113.10:443?security=reality&pbk=key&sid=aa&sni=example.com&type=grpc&serviceName=one"
        b = "vless://same-user@203.0.113.11:443?security=reality&pbk=key&sid=aa&sni=example.com&type=grpc&serviceName=two"
        self.assertNotEqual(server_identity(a, "vless"), server_identity(b, "vless"))


if __name__ == "__main__":
    unittest.main()
