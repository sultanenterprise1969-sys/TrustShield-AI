import socket
import unittest
from unittest import mock

from scanners.url_parts import parse_url
from scanners.url_scanner import scan_url


def ids(r):
    return {i["id"] for i in r["indicators"]}


class UrlScanner(unittest.TestCase):
    def test_invalid_inputs_return_errors_not_crashes(self):
        for bad in ["", "   ", None, 123, "javascript:alert(1)", "ftp://x.com", "hello", "http://", "a b.com", "http://exa$mple.com", "x" * 3000]:
            r = scan_url(bad)
            self.assertFalse(r["ok"], bad)
            self.assertTrue(r["error"])

    def test_plain_http_alone_is_not_flagged_high(self):
        r = scan_url("http://example.org", use_model=False)
        self.assertEqual(ids(r), {"no_https"})
        self.assertLess(r["risk_score"], 30)

    def test_https_does_not_mean_safe(self):
        r = scan_url("https://paypa1.com/secure-login/verify", use_model=False)
        self.assertIn("lookalike_domain", ids(r))
        self.assertGreaterEqual(r["risk_score"], 30)

    def test_ip_address_host(self):
        self.assertIn("ip_host", ids(scan_url("http://192.168.4.5/login", use_model=False)))
        self.assertIn("ip_host", ids(scan_url("http://2130706433/", use_model=False)))  # decimal-obfuscated

    def test_brand_in_subdomain_is_high_risk(self):
        r = scan_url("http://paypal.secure-login.xyz/verify", use_model=False)
        self.assertIn("brand_in_host", ids(r))
        self.assertGreaterEqual(r["risk_score"], 30)  # rules alone: Suspicious or worse
        self.assertEqual(scan_url("http://paypal.secure-login.xyz/verify?next=http://x.test/", use_model=False)["risk_category"], "High Risk")

    def test_real_brand_domain_not_flagged_as_brand_abuse(self):
        r = scan_url("https://www.paypal.com/signin", use_model=False)
        self.assertNotIn("brand_in_host", ids(r))
        self.assertNotIn("lookalike_domain", ids(r))

    def test_common_word_not_mistaken_for_brand(self):
        self.assertNotIn("brand_in_host", ids(scan_url("https://purchase.com/shop", use_model=False)))

    def test_punycode_and_userinfo_and_shortener_and_redirect(self):
        self.assertIn("idn_homograph", ids(scan_url("https://xn--pypal-4ve.com/", use_model=False)))
        self.assertIn("at_symbol", ids(scan_url("http://google.com@evil.top/x", use_model=False)))
        self.assertIn("shortener", ids(scan_url("https://bit.ly/abc", use_model=False)))
        self.assertIn("redirect_param", ids(scan_url("https://good.com/r?url=http://evil.test/x", use_model=False)))

    def test_long_url_and_many_subdomains(self):
        self.assertIn("long_url", ids(scan_url("https://a.com/" + "x" * 200, use_model=False)))
        self.assertIn("many_subdomains", ids(scan_url("http://a.b.c.d.example.com/", use_model=False)))

    def test_missing_scheme_is_handled(self):
        r = scan_url("example.com/page", use_model=False)
        self.assertTrue(r["ok"])
        self.assertNotIn("no_https", ids(r))

    def test_never_opens_network_connections(self):
        with mock.patch.object(socket, "create_connection", side_effect=AssertionError("network used!")), \
             mock.patch.object(socket.socket, "connect", side_effect=AssertionError("network used!")):
            self.assertTrue(scan_url("http://evil.example.top/login?next=http://x.y")["ok"])

    def test_local_only_limitation_is_stated(self):
        r = scan_url("https://example.com", use_model=False)
        self.assertTrue(any("LOCAL analysis" in l for l in r["limitations"]))

    def test_multi_part_suffix(self):
        self.assertEqual(parse_url("https://www.bbc.co.uk/news")["registered_domain"], "bbc.co.uk")


if __name__ == "__main__":
    unittest.main()
