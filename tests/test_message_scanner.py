import unittest

from scanners.message_scanner import extract_urls, scan_message


def ids(r):
    return {i["id"] for i in r["indicators"]}


PHISH = ("URGENT: Your PayPal account has been suspended. Verify your password and OTP within 24 hours at "
         "http://paypal-secure-login.xyz/verify or we will take legal action.")


class MessageScanner(unittest.TestCase):
    def test_empty_inputs(self):
        for bad in ["", "   ", None]:
            self.assertFalse(scan_message(bad)["ok"])

    def test_phishing_message_is_high_risk_with_snippets(self):
        r = scan_message(PHISH, sender="alerts@paypa1-support.com")
        self.assertEqual(r["risk_category"], "High Risk")
        self.assertTrue({"credential_request", "urgency", "account_threat", "suspicious_link"} <= ids(r))
        cred = next(i for i in r["indicators"] if i["id"] == "credential_request")
        self.assertTrue(cred["evidence"])
        self.assertEqual(r["extracted_urls"], ["http://paypal-secure-login.xyz/verify"])

    def test_normal_message_is_low(self):
        r = scan_message("Hi Sam, are we still meeting for lunch tomorrow at 1pm? I booked the table near the library.")
        self.assertEqual(r["risk_category"], "Low Risk")
        self.assertEqual(r["indicators"], [])

    def test_security_warning_is_not_flagged_as_credential_request(self):
        r = scan_message("Bank notice: never share your OTP with anyone. We will never ask for your password by SMS.")
        self.assertNotIn("credential_request", ids(r))

    def test_very_short_text_is_insufficient_evidence(self):
        r = scan_message("ok")
        self.assertIn("Insufficient evidence", r["display_category"])

    def test_prize_and_gift_card(self):
        r = scan_message("Congratulations! You have won a free iPhone. Pay the small fee by gift card to claim your prize.")
        self.assertTrue({"prize", "unusual_payment"} <= ids(r))

    def test_sender_brand_mismatch(self):
        r = scan_message("Your Amazon order needs attention, please review the details of your recent purchase today.",
                         sender="Amazon <deals@gmail.com>")
        self.assertIn("sender_brand_mismatch", ids(r))

    def test_url_extraction_strips_punctuation_and_dedupes(self):
        self.assertEqual(extract_urls("see http://a.com/x, and (http://a.com/x). also bit.ly/zz!"), ["http://a.com/x", "bit.ly/zz"])

    def test_too_long_text_rejected(self):
        self.assertFalse(scan_message("a " * 20000)["ok"])

    def test_limitations_present_and_say_not_proof(self):
        self.assertTrue(any("not proof" in l for l in scan_message(PHISH)["limitations"]))


if __name__ == "__main__":
    unittest.main()
