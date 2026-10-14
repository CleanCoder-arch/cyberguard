
import unittest

from cyberguard_url import analyze_url
from cyberguard_sms import analyze_sms
from sms_url_extractor import extract_urls
from cyberguard import analyze_input


class TestCyberGuard(unittest.TestCase):

    def test_legitimate_url_returns_valid_result(self):
        result = analyze_url("https://www.wikipedia.org")

        self.assertIn(
            result["risk_level"],
            ["LOW", "MEDIUM", "HIGH"]
        )
        self.assertGreaterEqual(result["risk_score"], 0)
        self.assertLessEqual(result["risk_score"], 100)
        self.assertGreaterEqual(
            result["malicious_probability"], 0
        )
        self.assertLessEqual(
            result["malicious_probability"], 1
        )

    def test_suspicious_url_is_high_risk(self):
        result = analyze_url(
            "http://secure-login-bank.xyz/verify"
        )

        self.assertEqual(result["risk_level"], "HIGH")
        self.assertGreaterEqual(result["risk_score"], 60)

    def test_at_symbol_url_uses_actual_hostname(self):
        result = analyze_url(
            "http://google.com@evil-site.xyz/login"
        )

        self.assertEqual(
            result["hostname"],
            "evil-site.xyz"
        )
        self.assertEqual(result["risk_level"], "HIGH")

    def test_ip_address_url_is_detected(self):
        result = analyze_url(
            "http://192.168.1.100/login"
        )

        self.assertEqual(result["hostname"], "192.168.1.100")
        self.assertIn(
            "URL uses an IP address instead of a normal domain.",
            result["reasons"]
        )

    def test_sms_analyzer_returns_result(self):
        result = analyze_sms(
            "URGENT! Your bank account is suspended. "
            "Verify immediately."
        )

        self.assertIsInstance(result, dict)

    def test_sms_extractor_finds_multiple_urls(self):
        message = (
            "Security alert! Visit http://evil1.xyz/login "
            "or https://evil2.top/verify"
        )

        urls = extract_urls(message)

        self.assertEqual(len(urls), 2)

    def test_sms_extractor_ignores_email_address(self):
        urls = extract_urls(
            "Contact support@example.com for help."
        )

        self.assertEqual(urls, [])

    def test_normal_sms_combined_analysis(self):
        result = analyze_input(
            "SMS",
            "Your meeting is scheduled for tomorrow at 10 AM."
        )

        self.assertIsInstance(result, dict)
        self.assertIn(
            "combined_risk",
            result
        )

    def test_phishing_sms_with_url(self):
        result = analyze_input(
            "SMS",
            "URGENT! Your bank account has been suspended. "
            "Verify immediately at "
            "http://secure-login-bank.xyz/verify"
        )

        self.assertIsInstance(result, dict)
        self.assertIn("combined_risk", result)

        combined = result["combined_risk"]

        self.assertGreaterEqual(
            combined["risk_score"], 60
        )
        self.assertEqual(
            combined["risk_level"], "HIGH"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
