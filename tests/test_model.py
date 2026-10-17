import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import config
from ai import predictor
from ai.features import FEATURE_NAMES, extract_features
from ai.model_training import train
from scanners.url_scanner import scan_url


class Features(unittest.TestCase):
    def test_feature_vector_shape_and_invalid_input(self):
        f = extract_features("https://example.com/a?b=1")
        self.assertEqual(len(f), len(FEATURE_NAMES))
        for bad in ["", None, "javascript:x", "nope"]:
            self.assertIsNone(extract_features(bad))


class Training(unittest.TestCase):
    def test_train_save_load_predict(self):
        if not config.TRAINING_CSV.exists():
            self.skipTest("run data/generate_synthetic_data.py first")
        with tempfile.TemporaryDirectory() as d:
            mp, jp = Path(d) / "m.joblib", Path(d) / "metrics.json"
            m = train(model_path=mp, metrics_path=jp)
            self.assertEqual(m["split"]["train"] + m["split"]["test"], m["rows_used"])
            self.assertEqual(sum(m["class_distribution"].values()), m["rows_used"])
            self.assertTrue(m["dataset_is_synthetic"])
            self.assertEqual(json.loads(jp.read_text())["f1"], m["f1"])
            predictor.reset_cache()
            p = predictor.predict_url("http://paypal.secure-login.xyz/verify", path=mp)
            self.assertTrue(p["available"])
            self.assertIn("uncalibrated", p["score_note"])

    def test_bad_training_data_raises_clear_error(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "tiny.csv"
            f.write_text("url,label\nhttp://a.com,0\nhttp://b.com,1\n")
            with self.assertRaises(ValueError):
                train(csv_path=f, model_path=Path(d) / "m", metrics_path=Path(d) / "j")


class ModelFailure(unittest.TestCase):
    def tearDown(self):
        predictor.reset_cache()

    def test_missing_model_falls_back_to_rules(self):
        predictor.reset_cache()
        with mock.patch.object(config, "MODEL_PATH", Path("/nonexistent/model.joblib")):
            r = scan_url("http://paypal.secure-login.xyz/verify/account?redirect=http://evil.test/x")
        self.assertTrue(r["ok"])
        self.assertFalse(r["model"]["available"])
        self.assertEqual(r["risk_category"], "High Risk")  # rules alone still catch it
        self.assertTrue(any("ML model unavailable" in l for l in r["limitations"]))

    def test_corrupted_model_file_does_not_crash(self):
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "bad.joblib"
            bad.write_bytes(b"this is not a model")
            predictor.reset_cache()
            p = predictor.predict_url("http://example.com", path=bad)
        self.assertFalse(p["available"])


if __name__ == "__main__":
    unittest.main()
