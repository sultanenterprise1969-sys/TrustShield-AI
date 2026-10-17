import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import config
from tests.helpers import make_png

HAVE = all(importlib.util.find_spec(m) for m in ("fastapi", "httpx", "multipart"))


@unittest.skipUnless(HAVE, "fastapi/httpx/python-multipart not installed (pip install -r requirements.txt)")
class Api(unittest.TestCase):
    def setUp(self):
        from fastapi.testclient import TestClient
        import api
        self.tmp = tempfile.TemporaryDirectory()
        self.p = mock.patch.object(config, "DB_PATH", Path(self.tmp.name) / "h.db")
        self.p.start()
        self.c = TestClient(api.app, raise_server_exceptions=False)

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    def test_health(self):
        j = self.c.get("/api/health").json()
        self.assertTrue(j["ok"])

    def test_url_scan_and_history(self):
        j = self.c.post("/api/scan/url", json={"url": "http://paypal.secure-login.xyz/verify"}).json()
        self.assertTrue(j["ok"])
        self.assertEqual(j["data"]["risk_category"], "High Risk")
        self.assertEqual(len(self.c.get("/api/history").json()["data"]["scans"]), 1)

    def test_errors_are_consistent_json(self):
        r = self.c.post("/api/scan/url", json={"url": "javascript:alert(1)"})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(set(r.json()), {"ok", "data", "error"})
        self.assertEqual(self.c.post("/api/scan/url", json={}).status_code, 422)
        self.assertEqual(self.c.post("/api/scan/message", json={"body": "  "}).status_code, 400)

    def test_image_validation_over_http(self):
        r = self.c.post("/api/scan/image", files={"file": ("x.png", b"not an image", "image/png")})
        self.assertEqual(r.status_code, 400)
        ok = self.c.post("/api/scan/image", files={"file": ("x.png", make_png(), "image/png")})
        self.assertEqual(ok.status_code, 200)

    def test_oversized_request_rejected(self):
        r = self.c.post("/api/scan/image", content=b"0" * (config.MAX_UPLOAD_BYTES + 200_000), headers={"content-type": "application/octet-stream"})
        self.assertEqual(r.status_code, 413)


if __name__ == "__main__":
    unittest.main()
