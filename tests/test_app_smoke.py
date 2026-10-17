"""Runs every page of app.py against a stub 'streamlit' so wiring bugs are caught without a browser.
(With real Streamlit installed you can also use:  streamlit run app.py)"""
import runpy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import config
from tests.helpers import make_png


def make_stub(page, **inputs):
    st = mock.MagicMock()
    st.session_state = {}
    st.sidebar.radio.return_value = page
    st.sidebar.checkbox.return_value = True
    st.radio.return_value = inputs.get("source", "Bundled synthetic sample")
    st.button.return_value = True
    st.checkbox.return_value = True
    st.text_input.return_value = inputs.get("text_input", "http://paypal.secure-login.xyz/verify")
    st.text_area.return_value = inputs.get("text_area", "URGENT verify your password at http://bit.ly/abc")
    st.columns.side_effect = lambda spec: [st for _ in range(spec if isinstance(spec, int) else len(spec))]
    up = mock.MagicMock()
    up.name, up.type, up.getvalue.return_value = "a.png", "image/png", make_png()
    st.file_uploader.return_value = inputs.get("upload", up)
    return st


class AppSmoke(unittest.TestCase):
    def run_page(self, page, **inputs):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(config, "DB_PATH", Path(d) / "h.db"):
            st = make_stub(page, **inputs)
            with mock.patch.dict(sys.modules, {"streamlit": st}):
                runpy.run_path(str(config.BASE_DIR / "app.py"))
            return st

    def test_all_pages_render_without_exceptions(self):
        for page in ["Dashboard", "Scan a Link", "Scan an Email or Message", "Scan an Image",
                     "Login Threat Analysis", "Scan History", "About & Safety"]:
            with self.subTest(page=page):
                self.run_page(page)

    def test_invalid_inputs_show_errors_not_crashes(self):
        st = self.run_page("Scan a Link", text_input="javascript:alert(1)")
        st.error.assert_called()
        st = self.run_page("Scan an Email or Message", text_area="", text_input="")
        st.error.assert_called()

    def test_login_page_with_bad_csv_upload(self):
        up = mock.MagicMock()
        up.name, up.getvalue.return_value = "x.csv", b"a,b\n1,2\n"
        st = self.run_page("Login Threat Analysis", source="Upload my own CSV", upload=up)
        st.error.assert_called()


if __name__ == "__main__":
    unittest.main()
