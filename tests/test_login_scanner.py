import unittest

import config
from scanners.login_scanner import analyze_logins, load_login_csv


class LoginScanner(unittest.TestCase):
    def test_sample_data_flags_attack_patterns_only(self):
        res = analyze_logins(load_login_csv(config.SAMPLE_LOGIN_CSV))
        high = res[res["risk_category"] == "High Risk"]
        self.assertGreater(len(high), 0)
        self.assertLess(len(high), len(res) * 0.1)  # normal traffic is mostly left alone
        self.assertTrue(set(high["user_id"]) & {"U003", "U005"})
        self.assertTrue(high["reason"].str.contains("failed").any())
        self.assertTrue(res["recommended_response"].notna().all())

    def test_missing_columns_error(self):
        with self.assertRaises(ValueError):
            load_login_csv(b"timestamp,user_id\n2026-01-01 10:00,U1\n")

    def test_garbage_and_empty_csv(self):
        for data in [b"", b"\x00\x01\x02", b"timestamp,user_id,failed_attempts,country,device_type,ip_address,login_success\n"]:
            with self.assertRaises(ValueError):
                load_login_csv(data)

    def test_new_country_needs_baseline(self):
        csv = "timestamp,user_id,failed_attempts,country,device_type,ip_address,login_success\n"
        for i in range(4):
            csv += f"2026-01-0{i+1} 10:00,U1,0,Malaysia,desktop,192.0.2.1,1\n"
        csv += "2026-01-09 10:00,U1,0,Peru,desktop,192.0.2.9,1\n"
        res = analyze_logins(load_login_csv(csv.encode()))
        self.assertIn("Country not seen before", res.iloc[-1]["reason"])
        self.assertNotIn("Country not seen before", res.iloc[0]["reason"])


if __name__ == "__main__":
    unittest.main()
