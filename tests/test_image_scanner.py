import shutil
import unittest
from unittest import mock

import config
from scanners import image_scanner
from scanners.image_scanner import scan_image
from tests.helpers import make_png
from utils.validation import validate_image_upload

PNG = make_png()


class ImageValidation(unittest.TestCase):
    def test_rejects_bad_uploads(self):
        cases = [
            ("a.png", "image/png", b""),                                   # empty
            ("a.gif", "image/gif", PNG),                                   # extension
            ("a.png", "application/pdf", PNG),                            # MIME
            ("a.png", "image/png", b"not an image at all"),               # signature
            ("a.jpg", "image/jpeg", PNG),                                  # ext/content mismatch
            ("a.png", "image/png", PNG + b"0" * (config.MAX_UPLOAD_BYTES + 1)),  # too large
        ]
        for name, mime, data in cases:
            self.assertIsNotNone(validate_image_upload(name, mime, data), name)

    def test_accepts_valid_png(self):
        self.assertIsNone(validate_image_upload("shot.PNG", "image/png", PNG))

    def test_scan_image_returns_error_for_invalid_file(self):
        r = scan_image("evil.png", "image/png", b"\x89PNG\r\n\x1a\n" + b"garbage")
        self.assertFalse(r["ok"])  # right signature, corrupt body -> friendly error, no crash


class ImageScanning(unittest.TestCase):
    def test_ocr_missing_is_handled_gracefully(self):
        fake = {"status": "unavailable", "text": "", "confidence": None, "message": "Tesseract OCR is not installed"}
        with mock.patch.object(image_scanner, "run_ocr", return_value=fake):
            r = scan_image("a.png", "image/png", PNG)
        self.assertTrue(r["ok"])
        self.assertIn("Insufficient evidence", r["display_category"])
        self.assertTrue(any("Tesseract" in l for l in r["limitations"]))

    def test_ocr_crash_is_handled(self):
        import pytesseract
        with mock.patch.object(pytesseract, "image_to_data", side_effect=RuntimeError("boom")):
            r = scan_image("a.png", "image/png", PNG)
        self.assertTrue(r["ok"])
        self.assertEqual(r["ocr"]["status"], "failed")

    def test_blank_image_has_insufficient_evidence(self):
        r = scan_image("blank.png", "image/png", PNG)
        self.assertTrue(r["ok"])
        self.assertIn("Insufficient evidence", r["display_category"])

    def test_text_is_passed_through_message_pipeline(self):
        fake = {"status": "ok", "confidence": 90.0, "message": "",
                "text": "URGENT: your account is suspended. Verify your password at http://paypal-secure-login.xyz/verify now"}
        with mock.patch.object(image_scanner, "run_ocr", return_value=fake):
            r = scan_image("a.png", "image/png", PNG)
        self.assertEqual(r["scan_type"], "image")
        self.assertEqual(r["risk_category"], "High Risk")
        self.assertTrue(any("orged logos" in l for l in r["limitations"]))

    @unittest.skipUnless(shutil.which("tesseract"), "Tesseract not installed")
    def test_real_ocr_end_to_end(self):
        png = make_png("URGENT verify your password\nhttp://bit.ly/abc123")
        r = scan_image("shot.png", "image/png", png)
        self.assertTrue(r["ok"])
        self.assertEqual(r["ocr"]["status"], "ok")
        self.assertIn("password", r["ocr"]["text"].lower())


if __name__ == "__main__":
    unittest.main()
