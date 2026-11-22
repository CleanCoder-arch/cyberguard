
import unittest
from unittest.mock import patch

from cyberguard_url import analyze_url
from cyberguard_sms import analyze_sms
from detector_models import DetectorUnavailableError
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

    def test_sms_scoring_and_link_checks_share_one_extraction(self):
        first = "https://example.com/Case?key=ABC"
        second = "https://example.com/Case?key=abc"
        message = f"See {first}, {first}, or {second}. Email me@sub.example.com."

        with patch("cyberguard.extract_urls", wraps=extract_urls) as extractor:
            result = analyze_input("SMS", message)

        extractor.assert_called_once_with(message)
        self.assertEqual(result["detected_urls"], [first, second])
        self.assertEqual(result["sms_result"]["detected_urls"], [first, second])
        self.assertEqual([link["url"] for link in result["url_results"]], [first, second])

    def test_malformed_embedded_url_leaves_scan_incomplete(self):
        invalid = "https://example.com:70000/"
        result = analyze_input("SMS", f"See https://example.com/ and {invalid}")

        self.assertIsNotNone(result["sms_result"])
        self.assertEqual(result["url_results"][0]["hostname"], "example.com")
        self.assertEqual(result["url_results"][1]["url"], invalid)
        self.assertIn("port", result["url_results"][1]["error"].lower())
        self.assertIsNone(result["combined_risk"])

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


class TestUnavailableDetectors(unittest.TestCase):

    def test_missing_sms_model_preserves_url_checks(self):
        with patch("cyberguard_sms.MODEL_PATH", "models/missing_sms_model.joblib"):
            url = "https://www.wikipedia.org"
            direct_result = analyze_input("URL", url)
            result = analyze_input("SMS", f"See {url}")

        self.assertIsNone(result["sms_result"])
        self.assertIn("SMS detector is unavailable", result["sms_error"])
        self.assertEqual(result["url_results"], [direct_result])
        self.assertIsNone(result["combined_risk"])

    def test_missing_url_model_preserves_sms_checks(self):
        with patch("cyberguard_url.MODEL_PATH", "models/missing_url_model.joblib"):
            with self.assertRaisesRegex(
                DetectorUnavailableError, "URL detector is unavailable"
            ):
                analyze_input("URL", "https://www.wikipedia.org")
            linked_sms = analyze_input("SMS", "See https://www.wikipedia.org")
            plain_sms = analyze_input("SMS", "See you tomorrow")

        self.assertIsNotNone(linked_sms["sms_result"])
        self.assertIn(
            "URL detector is unavailable", linked_sms["url_results"][0]["error"]
        )
        self.assertIsNone(linked_sms["combined_risk"])
        self.assertIsNotNone(plain_sms["combined_risk"])

    def test_one_failed_link_withholds_overall_risk(self):
        successful_url = "https://www.wikipedia.org"
        failed_url = "https://www.example.com"
        successful_result = analyze_url(successful_url)
        with patch(
            "cyberguard.analyze_url",
            side_effect=[successful_result, ValueError("Check failed")],
        ):
            result = analyze_input("SMS", f"See {successful_url} or {failed_url}")

        self.assertIsNotNone(result["sms_result"])
        self.assertEqual(result["url_results"], [
            successful_result,
            {"url": failed_url, "error": "Check failed"},
        ])
        self.assertIsNone(result["combined_risk"])

    def test_failed_link_extraction_preserves_sms_check(self):
        with patch("cyberguard.extract_urls", side_effect=ValueError("Extraction failed")):
            result = analyze_input("SMS", "See https://www.wikipedia.org")

        self.assertIn("risk_score", result["sms_result"])
        self.assertEqual(result["url_extraction_error"], "Extraction failed")
        self.assertIsNone(result["combined_risk"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
