import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

from url_normalizer import URLValidationError


APP_PATH = Path(__file__).with_name("app.py").resolve()
HISTORY_PATH = Path("data/scan_history.csv")
URL_RESULT = {
    "url": "https://example.com",
    "hostname": "example.com",
    "risk_score": 10,
    "risk_level": "LOW",
    "recommendation": "Verify the destination before proceeding.",
    "ml_prediction": "LEGITIMATE",
    "malicious_probability": 0.1,
    "reasons": [],
    "positive_signals": [],
}


class TestScannerApp(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.addCleanup(os.chdir, Path.cwd())
        os.chdir(temp.name)

        analysis = patch("cyberguard.analyze_input", return_value=URL_RESULT)
        self.analyze_input = analysis.start()
        self.addCleanup(analysis.stop)

        self.app = AppTest.from_file(str(APP_PATH), default_timeout=15).run()
        self.select_page("🔍 Scanner")

    def select_page(self, page):
        self.app.sidebar.radio[0].set_value(page).run()
        self.assertFalse(self.app.exception)

    def scan_url(self, url):
        self.app.text_input[0].set_value(url)
        self.app.button[0].click().run()

    def assert_report_visible(self, visible):
        self.assertFalse(self.app.exception)
        self.assertEqual(
            "📋 Analysis Result" in [item.value for item in self.app.subheader],
            visible,
        )

    def test_input_type_edits_and_navigation_clear_completed_report(self):
        self.assert_report_visible(False)
        self.scan_url("https://example.com")
        self.assert_report_visible(True)
        self.assertTrue(HISTORY_PATH.is_file())
        self.analyze_input.assert_called_once_with("URL", "https://example.com")

        self.app.text_input[0].set_value("https://example.org").run()
        self.assert_report_visible(False)
        self.analyze_input.assert_called_once()

        self.scan_url("https://example.org")
        self.assert_report_visible(True)
        self.app.main.radio[0].set_value("SMS / Message").run()
        self.assert_report_visible(False)
        self.app.main.radio[0].set_value("URL").run()
        self.assert_report_visible(False)

        self.scan_url("https://example.com")
        self.assert_report_visible(True)
        self.select_page("📊 Analytics")
        self.assert_report_visible(False)
        self.select_page("🔍 Scanner")
        self.assert_report_visible(False)

    def test_partial_sms_shows_completed_checks_without_overall_verdict(self):
        failed_url = "https://example.org"
        self.analyze_input.return_value = {
            "sms_result": {
                "risk_score": 40,
                "risk_level": "MEDIUM",
                "ml_prediction": "PHISHING/SPAM",
                "phishing_probability": 0.4,
                "reasons": ["SMS check found a warning sign."],
                "positive_signals": [],
            },
            "detected_urls": [URL_RESULT["url"], failed_url],
            "url_results": [
                URL_RESULT,
                {"url": failed_url, "error": "Link check failed."},
            ],
            "combined_risk": None,
        }
        self.app.main.radio[0].set_value("SMS / Message").run()
        self.app.text_area[0].set_value(
            "Meeting at https://example.com or https://example.org"
        )
        self.app.button[0].click().run()

        self.assert_report_visible(True)
        metrics = {metric.label: metric.value for metric in self.app.metric}
        self.assertEqual(metrics["SMS Risk Score"], "40/100")
        self.assertEqual(metrics["URL Risk"], "10/100")
        self.assertNotIn("Overall Risk", metrics)
        self.assertNotIn("Combined Risk", metrics)
        self.assertIn(
            "Analysis incomplete. An overall verdict is unavailable.",
            [item.value for item in self.app.warning],
        )
        self.assertTrue(any(failed_url in item.value for item in self.app.error))
        self.assertFalse(HISTORY_PATH.exists())

    def test_failed_url_rescan_clears_existing_report(self):
        self.scan_url("https://example.com")
        self.assert_report_visible(True)

        self.analyze_input.side_effect = RuntimeError("URL check failed.")
        self.app.button[0].click().run()

        self.assert_report_visible(False)
        self.assertTrue(self.app.error)

    def test_url_report_displays_unknown_scheme_and_validation_error(self):
        self.analyze_input.return_value = {**URL_RESULT, "scheme": "unknown"}
        self.scan_url("example.com")
        self.assert_report_visible(True)
        self.assertTrue(
            any("**Scheme:** unknown" in item.value for item in self.app.markdown)
        )

        self.analyze_input.side_effect = URLValidationError("Invalid URL: invalid port")
        self.scan_url("https://example.com:70000/")
        self.assert_report_visible(False)
        self.assertEqual(
            [item.value for item in self.app.error], ["Invalid URL: invalid port"]
        )


if __name__ == "__main__":
    unittest.main()
