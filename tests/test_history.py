import tempfile
import unittest
from pathlib import Path

from services import history


class History(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "h.db"

    def tearDown(self):
        self.tmp.cleanup()

    def test_add_list_stats_delete(self):
        self.assertEqual(history.list_scans(db_path=self.db), [])
        history.add_scan("url", "High Risk", 80, "evil.test: brand", db_path=self.db)
        history.add_scan("message", "Low Risk", 5, "ok", db_path=self.db)
        rows = history.list_scans(db_path=self.db)
        self.assertEqual([r["scan_type"] for r in rows], ["message", "url"])
        s = history.stats(db_path=self.db)
        self.assertEqual((s["total"], s["high_risk"], s["low_risk"]), (2, 1, 1))
        self.assertEqual(history.delete_all(db_path=self.db), 2)
        self.assertEqual(history.stats(db_path=self.db)["total"], 0)

    def test_sql_injection_text_is_stored_as_plain_text(self):
        evil = "x'); DROP TABLE scans;--"
        history.add_scan("url", "Low Risk", 0, evil, db_path=self.db)
        self.assertEqual(history.list_scans(db_path=self.db)[0]["summary"], evil)

    def test_demo_rows_are_flagged(self):
        history.load_demo(db_path=self.db)
        self.assertEqual(history.stats(db_path=self.db)["demo_rows"], len(history.DEMO_ROWS))

    def test_summary_never_contains_message_body(self):
        from scanners.message_scanner import scan_message
        r = scan_message("My secret password is hunter2, please verify your password immediately at http://bit.ly/zzz")
        history.add_scan("message", r["risk_category"], r["risk_score"], r["summary"], db_path=self.db)
        self.assertNotIn("hunter2", history.list_scans(db_path=self.db)[0]["summary"])


if __name__ == "__main__":
    unittest.main()
