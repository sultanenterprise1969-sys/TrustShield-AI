import unittest

from services.risk_scoring import Indicator, assess, categorize


class RiskScoring(unittest.TestCase):
    def test_boundaries(self):
        for score, cat in [(0, "Low Risk"), (29, "Low Risk"), (30, "Suspicious"), (59, "Suspicious"), (60, "High Risk"), (100, "High Risk")]:
            self.assertEqual(categorize(score), cat, score)

    def test_same_indicator_not_double_counted(self):
        r = assess([Indicator("a", "A", 20, "", ["x"]), Indicator("a", "A", 20, "", ["y"])])
        self.assertEqual(r["risk_score"], 20)
        self.assertEqual(r["indicators"][0]["evidence"], ["x", "y"])

    def test_clamped_to_0_100(self):
        self.assertEqual(assess([Indicator(str(i), "x", 40) for i in range(5)])["risk_score"], 100)
        self.assertEqual(assess([Indicator("n", "neg", -50)])["risk_score"], 0)

    def test_insufficient_evidence_is_labelled(self):
        r = assess([], sufficient=False, insufficient_reason="too short")
        self.assertIn("Insufficient evidence", r["display_category"])
        self.assertEqual(r["limitations"][0], "too short")

    def test_result_always_has_required_fields(self):
        r = assess([Indicator("a", "A", 35)])
        for k in ("risk_score", "risk_category", "indicators", "limitations", "next_steps", "disclaimer"):
            self.assertIn(k, r)
        self.assertEqual(r["risk_category"], "Suspicious")


if __name__ == "__main__":
    unittest.main()
