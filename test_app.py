import os
import tempfile
import unittest
from datetime import date, datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from streamlit.testing.v1 import AppTest

from cyberguard import analyze_input as analyze_with_detectors
from phishing_feed import FEED_URL, REQUEST_TIMEOUT, PhishingFeedCache
from scan_history import ScanHistory
from url_normalizer import URLValidationError


APP_PATH = Path(__file__).with_name("app.py").resolve()
QR_FIXTURES = APP_PATH.parent / "tests" / "fixtures" / "qr"
HISTORY_PATH = Path("data/scan_history.sqlite3")
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
EXPLAINED_URL_RESULT = {
    **URL_RESULT,
    "ml_prediction": "MALICIOUS",
    "malicious_probability": 0.525,
    "model_explanation": {
        "scale": "log_odds",
        "positive_class": "MALICIOUS",
        "baseline": -0.4,
        "positive": [
            {"feature": "url_length", "kind": "url_structure", "contribution": 0.7, "value": 19}
        ],
        "negative": [{"feature": "example", "kind": "url_tfidf", "contribution": -0.2}],
        "other_contribution": 0.0,
        "total": 0.1,
    },
    "score_breakdown": {
        "starting_score": 0,
        "adjustments": [
            {"rule": "Model probability", "delta": 15},
            {"rule": "HTTPS scheme", "delta": -5},
        ],
        "final_score": 10,
    },
    "checks": [{"check": "URL analysis", "status": "completed"}],
}
FEED_MATCH = {
    "provider": "Phishunt",
    "status": "fresh",
    "matched": True,
    "refreshed_at": "2026-11-22T06:00:00+00:00",
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

    def upload_qr(self, filename):
        mime_type = "image/jpeg" if filename.endswith(".jpg") else "image/png"
        image = (QR_FIXTURES / filename).read_bytes()
        self.app.file_uploader[0].set_value((filename, image, mime_type)).run()

    def select_qr_with_offline_feed(self):
        self.analyze_input.side_effect = analyze_with_detectors
        fetch = Mock(return_value=b"https://EXAMPLE.COM\n")
        feed = PhishingFeedCache(
            Path("data/feed-fixture.sqlite3"),
            fetch=fetch,
            clock=lambda: datetime(2026, 11, 23, 6, tzinfo=timezone.utc),
        )
        feed.refresh_if_due()
        fetch.assert_called_once_with(FEED_URL, timeout=REQUEST_TIMEOUT)
        fetch.reset_mock()
        cache_patch = patch("cyberguard.get_feed_cache", return_value=feed)
        cache_patch.start()
        self.addCleanup(cache_patch.stop)
        self.app.main.radio[0].set_value("QR Image").run()
        return fetch

    def assert_report_visible(self, visible):
        self.assertFalse(self.app.exception)
        self.assertEqual(
            "📋 Analysis Result" in [item.value for item in self.app.subheader],
            visible,
        )

    def seed_history(self):
        history = ScanHistory(HISTORY_PATH)
        for day, scan_type, status, risk, latency, freshness in (
            (22, "URL", "completed", "LOW", 20, "fresh"),
            (22, "SMS", "incomplete", None, 80, "stale"),
            (23, "SMS", "completed", "HIGH", 140, "unavailable"),
            (23, "QR", "failed", None, 40, None),
            (23, "QR", "completed", "MEDIUM", 60, "fresh"),
        ):
            history.record(
                scan_type, status, risk_level=risk, latency_ms=latency, feed_freshness=freshness,
                timestamp=datetime(2026, 11, day, 12, tzinfo=timezone.utc),
            )

    def test_dashboard_counts_and_filters_match_saved_metadata(self):
        self.seed_history()
        self.select_page("🏠 Dashboard")
        metrics = {item.label: item.value for item in self.app.metric}
        self.assertEqual(metrics, {
            "Total scans": "5", "Completed": "3", "Incomplete": "1", "Failed": "1",
        })

        self.app.date_input[0].set_value(date(2026, 11, 22))
        self.app.date_input[1].set_value(date(2026, 11, 22))
        self.app.selectbox[0].set_value("SMS").run()
        self.assertFalse(self.app.exception)
        metrics = {item.label: item.value for item in self.app.metric}
        self.assertEqual(metrics, {
            "Total scans": "1", "Completed": "0", "Incomplete": "1", "Failed": "0",
        })
        table = self.app.dataframe[0].value
        self.assertEqual(table["input_type"].tolist(), ["SMS"])
        self.assertEqual(table["feed_freshness"].tolist(), ["Stale"])

        self.app.selectbox[0].set_value("QR").run()
        self.assertFalse(self.app.exception)
        self.assertIn("No scans match these filters.", self.app.info[0].value)

    def test_dashboard_shortcuts_open_each_scanner(self):
        for label, mode in (
            ("Scan a URL", "URL"), ("Scan an SMS", "SMS / Message"), ("Scan a QR image", "QR Image"),
        ):
            with self.subTest(mode=mode):
                self.select_page("🏠 Dashboard")
                next(button for button in self.app.button if button.label == label).click().run()
                self.assertFalse(self.app.exception)
                self.assertEqual(self.app.sidebar.radio[0].value, "🔍 Scanner")
                self.assertEqual(self.app.main.radio[0].value, mode)

    def test_analytics_shows_verdict_latency_and_feed_counts_when_benchmark_missing(self):
        self.seed_history()
        with patch("benchmark_results.load_stage3b_benchmark", return_value=None):
            self.select_page("📊 Analytics")

        metrics = {item.label: item.value for item in self.app.metric}
        self.assertEqual(metrics["Incomplete"], "1")
        self.assertEqual(metrics["Median latency"], "60.0 ms")
        self.assertEqual(metrics["95th percentile latency"], "128.0 ms")
        self.assertEqual(metrics["Measured scans"], "5")
        verdicts = self.app.dataframe[0].value.set_index("Input type")
        self.assertEqual(verdicts.loc["URL", "LOW"], 1)
        self.assertEqual(verdicts.loc["SMS", "HIGH"], 1)
        self.assertEqual(verdicts.loc["QR", "MEDIUM"], 1)
        freshness = self.app.dataframe[1].value.set_index("Cache state")["Scans"].to_dict()
        self.assertEqual(freshness, {"Fresh": 2, "Stale": 1, "Unavailable": 1, "Unrecorded": 1})
        self.assertIn("Locked Stage 3B benchmark results are missing", self.app.info[0].value)

    def test_input_type_edits_and_navigation_clear_completed_report(self):
        self.assert_report_visible(False)
        self.scan_url("https://example.com")
        self.assert_report_visible(True)
        self.assertEqual(ScanHistory(HISTORY_PATH).read()[0]["input_type"], "URL")
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
                {
                    **EXPLAINED_URL_RESULT,
                    "phishing_feed": {**FEED_MATCH, "status": "stale", "matched": False},
                },
                {
                    "url": failed_url,
                    "error": "Link check failed.",
                    "phishing_feed": {**FEED_MATCH, "status": "stale"},
                },
            ],
            "combined_risk": None,
            "checks": [
                {"check": "Link extraction", "status": "completed"},
                {"check": "SMS analysis", "status": "completed"},
                {"check": "URL analysis", "status": "completed", "url": URL_RESULT["url"]},
                {"check": "URL analysis", "status": "failed", "url": failed_url},
                {"check": "Overall risk", "status": "skipped"},
            ],
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
        self.assertIn("Unable to analyze this URL", [item.value for item in self.app.error])
        self.assertIn(
            "Phishunt phishing feed · Exact match found",
            [item.value for item in self.app.warning],
        )
        captions = [item.value for item in self.app.caption]
        self.assertIn("Phishunt phishing feed · No exact match", captions)
        self.assertIn(f"Stale cache · Last successful refresh {FEED_MATCH['refreshed_at']}", captions)
        checks = [item.value for item in self.app.text]
        self.assertIn(failed_url, checks)
        self.assertIn("Link check failed.", checks)
        self.assertIn("Completed · Link extraction", checks)
        self.assertIn("Completed · SMS analysis", checks)
        self.assertIn(f"Completed · URL analysis · {URL_RESULT['url']}", checks)
        self.assertIn(f"Failed · URL analysis · {failed_url}", checks)
        self.assertIn("Skipped · Overall risk", checks)
        self.assertIn("+15 points · Model probability", checks)
        self.assertEqual(self.app.dataframe[0].value["Type"].tolist(), ["URL structure", "URL text"])
        record, = ScanHistory(HISTORY_PATH).read()
        self.assertEqual((record["input_type"], record["scan_status"], record["risk_level"]), (
            "SMS", "incomplete", None,
        ))

    def test_url_report_explains_model_flag_and_low_risk(self):
        self.analyze_input.return_value = EXPLAINED_URL_RESULT
        self.scan_url("https://example.com")

        self.assert_report_visible(True)
        metrics = {metric.label: metric.value for metric in self.app.metric}
        self.assertEqual(metrics["Overall Risk"], "LOW")
        self.assertEqual(metrics["ML Malicious Probability"], "52.50%")
        self.assertIn("**Prediction:** MALICIOUS", [item.value for item in self.app.markdown])
        self.assertTrue(
            any("rules total 10/100. MEDIUM risk starts at 30." in item.value for item in self.app.caption)
        )
        contributions = self.app.dataframe[0].value
        self.assertEqual(contributions["Feature"].tolist(), ["url_length", "example"])
        self.assertEqual(contributions["Contribution"].tolist(), ["+0.700", "-0.200"])
        self.assertEqual(contributions["Input value"].iloc[0], "19")
        report = [item.value for item in self.app.text]
        self.assertIn("Starting score 0/100", report)
        self.assertIn("+15 points · Model probability", report)
        self.assertIn("-5 points · HTTPS scheme", report)
        self.assertIn("Final score 10/100", report)

    def test_feed_states_are_visible_alongside_url_verdict(self):
        self.analyze_input.return_value = {**EXPLAINED_URL_RESULT, "phishing_feed": FEED_MATCH}
        self.scan_url("https://example.com")

        self.assert_report_visible(True)
        self.assertIn(
            "Phishunt phishing feed · Exact match found",
            [item.value for item in self.app.warning],
        )
        self.assertIn(
            f"Fresh cache · Last successful refresh {FEED_MATCH['refreshed_at']}",
            [item.value for item in self.app.caption],
        )
        metrics = {metric.label: metric.value for metric in self.app.metric}
        self.assertEqual(metrics["Risk Score"], "10/100")
        self.assertEqual(metrics["Overall Risk"], "LOW")

        self.analyze_input.return_value = {
            **EXPLAINED_URL_RESULT,
            "phishing_feed": {
                **FEED_MATCH,
                "status": "unavailable",
                "matched": None,
                "refreshed_at": None,
            },
        }
        self.scan_url("https://example.com")

        self.assert_report_visible(True)
        self.assertIn(
            "Phishunt phishing feed · Cache unavailable",
            [item.value for item in self.app.info],
        )
        self.assertIn("No successful refresh yet", [item.value for item in self.app.caption])
        self.assertEqual({metric.label: metric.value for metric in self.app.metric}, metrics)

    def test_verdict_remains_visible_when_contributions_are_unavailable(self):
        self.analyze_input.return_value = {
            **EXPLAINED_URL_RESULT,
            "model_explanation": {"status": "unavailable"},
        }
        self.scan_url("https://example.com")

        self.assert_report_visible(True)
        metrics = {metric.label: metric.value for metric in self.app.metric}
        self.assertEqual(metrics["Overall Risk"], "LOW")
        self.assertIn(
            "Feature contributions are unavailable for this model.",
            [item.value for item in self.app.caption],
        )

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

    def test_qr_url_reuses_report_and_records_metadata_only(self):
        fetch = self.select_qr_with_offline_feed()
        self.upload_qr("url.png")
        self.app.button[0].click().run()

        self.assert_report_visible(True)
        self.analyze_input.assert_called_once_with("URL", "https://example.com")
        self.assertIn(
            "QR image decoded locally as a web URL.", [item.value for item in self.app.caption]
        )
        self.assertIn(
            "Phishunt phishing feed · Exact match found", [item.value for item in self.app.warning]
        )
        metrics = {item.label: item.value for item in self.app.metric}
        self.assertEqual(metrics["Risk Score"], "10/100")
        self.assertIn("path_len", self.app.dataframe[0].value["Feature"].tolist())
        self.assertIn("Decoded URL: https://example.com", [item.value for item in self.app.text])
        self.assertTrue(any(item.value.startswith("+10 points") for item in self.app.text))
        record, = ScanHistory(HISTORY_PATH).read()
        self.assertEqual(
            (record["input_type"], record["scan_status"], record["risk_level"], record["feed_freshness"]),
            ("QR", "completed", "LOW", "fresh"),
        )
        self.assertGreaterEqual(record["latency_ms"], 0)
        database = HISTORY_PATH.read_bytes()
        self.assertNotIn(b"https://example.com", database)
        self.assertNotIn((QR_FIXTURES / "url.png").read_bytes(), database)
        fetch.assert_not_called()

    def test_qr_text_reuses_sms_and_link_reports_and_stores_no_payload(self):
        self.scan_url("https://example.org/previous")
        self.analyze_input.reset_mock()
        fetch = self.select_qr_with_offline_feed()
        self.upload_qr("text.jpg")
        self.app.button[0].click().run()

        self.assert_report_visible(True)
        self.analyze_input.assert_called_once_with("SMS", "Meeting details: https://example.com/Agenda")
        captions = [item.value for item in self.app.caption]
        self.assertIn("QR image decoded locally as a text message.", captions)
        self.assertIn("Phishunt phishing feed · No exact match", captions)
        self.assertIn("https://example.com/Agenda", [item.value for item in self.app.text])
        self.assertFalse(any("https://example.com/Agenda" in item.value for item in self.app.markdown))
        self.assertTrue(any(item.label == "Combined Risk" for item in self.app.metric))
        self.assertGreaterEqual(len(self.app.dataframe), 2)
        qr, previous = ScanHistory(HISTORY_PATH).read()
        self.assertEqual((qr["input_type"], previous["input_type"]), ("QR", "URL"))
        self.assertNotIn(b"Meeting details: https://example.com/Agenda", HISTORY_PATH.read_bytes())
        fetch.assert_not_called()

    def test_invalid_qr_uploads_clear_previous_report_and_do_not_start_scan(self):
        self.app.main.radio[0].set_value("QR Image").run()
        self.upload_qr("url.png")
        self.app.button[0].click().run()
        self.assert_report_visible(True)
        self.analyze_input.reset_mock()

        for filename, description in (
            ("unreadable.png", "could not be read"),
            ("multiple.png", "multiple QR codes"),
            ("unsupported.png", "Wi-Fi credentials are unsupported"),
            ("payment.png", "Payment links are unsupported"),
        ):
            with self.subTest(filename=filename):
                self.upload_qr(filename)
                self.assert_report_visible(False)
                self.app.button[0].click().run()
                self.assert_report_visible(False)
                self.assertIn(description, self.app.error[0].value)
                self.assertNotIn("fixture-only", self.app.error[0].value)
        self.analyze_input.assert_not_called()
        scans = ScanHistory(HISTORY_PATH).read()
        self.assertEqual([row["scan_status"] for row in scans], ["failed"] * 4 + ["completed"])
        self.assertTrue(all(row["input_type"] == "QR" for row in scans))


if __name__ == "__main__":
    unittest.main()
