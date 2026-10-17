import os
import unittest
from unittest import mock

from ai import explainer
from scanners.url_scanner import scan_url


class Explainer(unittest.TestCase):
    def setUp(self):
        self.r = scan_url("http://paypal.secure-login.xyz/verify/account?redirect=http://evil.test/x", use_model=False)

    def test_template_works_without_any_key(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            e = explainer.explain(self.r, use_llm=True)  # asked for LLM but none configured
        self.assertEqual(e["source"], "template")
        self.assertTrue(e["what_looks_suspicious"] and e["avoid"] and e["safest_next_step"])
        self.assertIn("High Risk", e["summary"])

    def test_template_does_not_claim_blacklist_or_certainty(self):
        text = str(explainer.template_explanation(self.r)).lower()
        self.assertNotIn("blacklist", text)
        self.assertNotIn("confirmed fraud", text)

    def test_llm_failure_falls_back(self):
        env = {"LLM_ENABLED": "true", "LLM_API_URL": "https://llm.invalid/v1/chat/completions", "LLM_MODEL": "m"}
        with mock.patch.dict(os.environ, env), mock.patch.object(explainer, "_call_llm", side_effect=TimeoutError()):
            e = explainer.explain(self.r, use_llm=True)
        self.assertEqual(e["source"], "template")
        self.assertIn("LLM unavailable", e["llm_note"])

    def test_overclaiming_llm_output_is_rejected(self):
        env = {"LLM_ENABLED": "true", "LLM_API_URL": "https://llm.invalid/x", "LLM_MODEL": "m"}
        with mock.patch.dict(os.environ, env), mock.patch.object(explainer, "_call_llm", return_value="This is definitely a scam."):
            e = explainer.explain(self.r, use_llm=True)
        self.assertEqual(e["source"], "template")

    def test_llm_output_used_but_score_unchanged(self):
        env = {"LLM_ENABLED": "true", "LLM_API_URL": "https://llm.invalid/x", "LLM_MODEL": "m"}
        before = self.r["risk_score"]
        with mock.patch.dict(os.environ, env), mock.patch.object(explainer, "_call_llm", return_value="Looks risky; avoid the link."):
            e = explainer.explain(self.r, use_llm=True)
        self.assertEqual(e["source"], "llm")
        self.assertEqual(self.r["risk_score"], before)

    def test_payload_excludes_snippets_by_default(self):
        from scanners.message_scanner import scan_message
        m = scan_message("Please send your password hunter2 immediately to verify")
        payload = str(explainer._safe_payload(m, include_snippets=False))
        self.assertNotIn("hunter2", payload)

    def test_insecure_llm_url_refused(self):
        env = {"LLM_ENABLED": "true", "LLM_API_URL": "http://example.com/v1", "LLM_MODEL": "m"}
        with mock.patch.dict(os.environ, env), self.assertRaises(ValueError):
            explainer._call_llm({})


if __name__ == "__main__":
    unittest.main()
